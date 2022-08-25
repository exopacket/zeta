package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.Hex;
import com.inteliense.trusty.utils.SHA;
import org.json.simple.JSONObject;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

public abstract class API implements APIMethods {

    private APIServer server;
    private APIServerConfig serverConfig;
    private ArrayList<RemoteClient> clients;
    private ArrayList<String> blacklist;
    private ArrayList<RemoteClient> rateLimitedClients;

    public API(APIServerConfig config) throws APIException {
        this.serverConfig = config;
    }

    public void start() throws APIException {

        server = new APIServer(serverConfig) {

            @Override
            public APIKeyPair lookupApiKeys(String apiKey) {
                return null;
            }

            @Override
            public HashMap<String, String> parseRequestBody(RemoteClient client, String resource, String body) {
                return API.this.parseRequestBody(client, resource, body);
            }

            @Override
            public HashMap<String, String> decryptZeroTrust(JSONObject obj, ZeroTrustRequestType type) {
                return API.this.decryptZeroTrust(obj, type);
            }

            @Override
            public boolean isPastRateLimit(RemoteClient client, int perMinute) {
                return API.this.isPastRateLimit(client, perMinute);
            }

            @Override
            public boolean inBlacklist(RemoteClient client) {
                return API.this.inBlacklist(client);
            }

            @Override
            public RemoteClient initAuthentication(String apiKey, String ipAddress,
                                                   String port, String hostname,
                                                   HashMap<String, String> parameters) {
                return API.this.initAuthentication(apiKey, ipAddress, port, hostname, parameters);
            }

            @Override
            public boolean lookupApiKey(String apiKeyHeader) {
                return API.this.lookupApiKey(apiKeyHeader);
            }


            @Override
            public boolean lookupUserId(String apiKey, String clientId, String userId) {
                return API.this.lookupUserId(apiKey, clientId, userId);
            }

        };

    }

    public APIResource addResource(String value, APIResource definition) {

        return server.addResource(value, definition);

    }

    public APIResource addResource(String value, String[] parameters, APIResource definition) {
        return server.addResource(value, parameters, definition);
    }

    public APIResource addResource(String value, ArrayList<String> parameters, APIResource definition) {
        return server.addResource(value, parameters, definition);
    }

    public boolean isAuthenticated(RemoteClient client) {

        return lookupApiKey(client.getApiKey());

    }

    public boolean lookupUserId(String apiKey, String clientId, String userId) {

        //Returns false to indicate not found.
        //Default value when not implemented.
        return false;

    }

    //IF "POST" REQUEST IS NOT IN JSON FORMAT THIS MUST BE OVERRIDE
    public HashMap<String, String> parseRequestBody(RemoteClient client, String resource, String body) {
        return null;
    }

    //TODO CAN BE DONE
    public HashMap<String, String> decryptZeroTrust(JSONObject obj, ZeroTrustRequestType type) {

        return null;

    }

    //TODO CAN BE DONE
    public RemoteClient initAuthentication(String apiKey, String ipAddress,
                                           String port, String hostname,
                                           HashMap<String, String> parameters) {

            String userId = parameters.get("user_id");
            String clientId = parameters.get("client_id");
            String initHash = parameters.get("id_hash");
            String initHashCheck = Base64.getEncoder().encodeToString(
                    Hex.fromHex(SHA.get256(
                                    Base64.getEncoder().encodeToString(
                                            Hex.fromHex(SHA.getHmac256(ipAddress, apiKey))
                                    )
                            )
                    )
            );

            if(!initHash.equals(initHashCheck))
                return RemoteClient.NONE;

            if(!lookupUserId(apiKey, clientId, userId))
                return RemoteClient.NONE;

            int count = 1;

            for(int i=0; i<clients.size(); i++) {

                RemoteClient client = clients.get(i);
                if(client.getUserId().equals(userId)) {
                    count++;
                    continue;
                }
                if(client.getRemoteIp().equals(ipAddress)) {
                    count++;
                    continue;
                }

            }

            if(count > 0) {
                if(count > serverConfig.getMaxSessions())
                    return RemoteClient.NONE;
            }

            try {

                new RemoteClient(ipAddress, port, hostname, apiKey, clientId, userId, server) {
                    @Override
                    public boolean isLimited(int perMinute) {
                        return super.getServer().isPastRateLimit(this, serverConfig.getRequestsPerMinute());
                    }

                    @Override
                    public boolean inBlacklist() {
                        return super.getServer().inBlacklist(this);
                    }

                    @Override
                    public boolean isAuthenticated() {
                        return super.getServer().isAuthenticated(this);
                    }

                    @Override
                    public boolean lookupApiKey(String apiKeyHeader) {
                        return super.getServer().lookupApiKey(apiKeyHeader);
                    }

                    @Override
                    public boolean lookupUserId(String apiKey, String clientId, String userId) {
                        return super.getServer().lookupUserId(apiKey, clientId, userId);
                    }
                };

            } catch (APIException ex) {
                System.out.println(ex.getMessage());
            }

            return RemoteClient.NONE;

    }

    //TODO CAN BE DONE
    public boolean isPastRateLimit(RemoteClient client, int perMinute) {

        //Returns false to indicate not found.
        //Default value when not implemented.
        return false;

    }

    //TODO CAN BE DONE
    public boolean inBlacklist(RemoteClient client) {

        //Returns false to indicate not found.
        //Default value when not implemented.
        return false;

    }

}
