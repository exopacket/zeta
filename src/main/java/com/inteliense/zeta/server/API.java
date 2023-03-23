package com.inteliense.zeta.server;

import java.util.ArrayList;
import java.util.HashMap;

public abstract class API implements APIMethods {

    private APIServer server;
    private APIServerConfig serverConfig;
    private ArrayList<BlacklistEntry> blacklist = new ArrayList<BlacklistEntry>();
    private ArrayList<RemoteClient> rateLimitedClients = new ArrayList<RemoteClient>();

    public API(APIServerConfig config) throws APIException {
        this.serverConfig = config;
    }

    public void start() throws APIException {

        server = new APIServer(serverConfig) {

            @Override
            public HashMap<String, String> getParameters(String body, ContentType contentType) {
                return API.this.getParameters(body, contentType);
            }

            @Override
            public boolean isPastRateLimit(ClientSession clientSession, int perMinute) {
                return API.this.inTimeout(clientSession, perMinute);
            }

            @Override
            public boolean inBlacklist(ClientSession clientSession) {
                return API.this.inBlacklist(clientSession);
            }

            @Override
            public boolean isAuthenticated(RequestHeaders headers, APIResource resource, Parameters params, ClientSession clientSession) {
                return API.this.isAuthenticated(headers, resource, params, clientSession);
            }

            @Override
            public boolean lookupUserInfo(ClientSession clientSession) {
                return API.this.lookupUserInfo(clientSession);
            }

            @Override
            public APIKeyPair lookupApiKeys(String apiKey) {
                return API.this.lookupApiKey(apiKey);
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

    public APIResource addResource(String value, boolean isAsync, ArrayList<String> parameters, APIResource definition) {

        if(serverConfig.getServerResponseType() == APIServerType.ZERO_TRUST_SYNC
                || serverConfig.getServerResponseType() == APIServerType.REST_SYNC) {
            return server.addResource(value, parameters, definition);
        }

        return server.addResource(value, isAsync, parameters, definition);
    }

    public APIResource addResource(String value, boolean isAsync, APIResource definition) {

        if(serverConfig.getServerResponseType() == APIServerType.ZERO_TRUST_SYNC
                || serverConfig.getServerResponseType() == APIServerType.REST_SYNC) {
            return server.addResource(value, definition);
        }

        return server.addResource(value, isAsync, definition);

    }

    public APIResource addResource(String value, boolean isAsync, String[] parameters, APIResource definition) {

        if(serverConfig.getServerResponseType() == APIServerType.ZERO_TRUST_SYNC
                || serverConfig.getServerResponseType() == APIServerType.REST_SYNC) {
            return server.addResource(value, parameters, definition);
        }

        return server.addResource(value, isAsync, parameters, definition);

    }

    //IF REQUEST BODY IS NOT IN JSON FORMAT THIS MUST BE OVERRIDE
    public HashMap<String, String> getParameters(String body, ContentType contentType) {
        return new HashMap<String, String>();
    }

    public boolean isAuthenticated(RequestHeaders headers, APIResource resource, Parameters params, ClientSession clientSession) {

        if(headers.contains("X-Api-Session-Id")) {

            String apiKey = headers.getString("X-Api-Key");
            String sessionId = headers.getString("X-Api-Session-Id");
            String keySetId = headers.getString("X-Api-Key-Set-Id");
            //String userId = headers.getString("X-Api-User-Id");
            //String clientId = headers.getString("X-Api-Client-Id");
            String sessionAuth = headers.getString("X-Api-Session-Authorization");

            boolean flag = false;

            if(!apiKey.equals(clientSession.getClient().getApiKey()))
                flag = true;

            if(!sessionId.equals(clientSession.getSession().getSessionId()))
                flag = true;

            if(!keySetId.equals(clientSession.getSession().getKeySetId()))
                flag = true;
//
//            if(!userId.equals(clientSession.getSession().getUserId()))
//                flag = true;
//
//            if(!clientId.equals(clientSession.getSession().getClientId()))
//                flag = true;

            if(!clientSession.getSession().checkDynamicSessionAuth(sessionAuth))
                flag = true;

            if(flag) {
                APIServer server = clientSession.getClient().getServer();
                server.invalidateSession(clientSession);
            }

            return !flag;

        } else {

            String apiKey = headers.getString("X-Api-Key");

            if(!apiKey.equals(clientSession.getClient().getApiKey()))
                return false;

            return true;

        }

    }

    public boolean lookupUserInfo(ClientSession clientSession) {

        //Returns true to indicate user info was found.
        //Default value when not implemented.
        return true;

    }
    public boolean inTimeout(ClientSession clientSession, int perMinute) {

        if(clientSession.getSession().getRecentRequests() >= perMinute) {
            return true;
        }

        return false;

    }

    public boolean inBlacklist(ClientSession clientSession) {

        for(int i=0; i<blacklist.size(); i++) {

            BlacklistEntry entry = blacklist.get(i);
            BlacklistEntryType type = entry.getEntryType();
            String value = entry.getValue();

            boolean found = false;

            switch(type) {
                case API_KEY:
                    found = value.equals(clientSession.getClient().getApiKey());
                    break;
                case USER_ID:
                    found = value.equals(clientSession.getSession().getUserId());
                    break;
                case CLIENT_ID:
                    found = value.equals(clientSession.getSession().getClientId());
                    break;
                case IP_ADDRESS:
                    found = value.equals(clientSession.getClient().getClientInfo().getRemoteIp());
                    break;
            }

            if(found)
                return true;

        }

        return false;

    }

    public void addToBlacklist(ClientSession clientSession, BlacklistEntryType entryType) {
        blacklist.add(0, new BlacklistEntry(entryType, clientSession));
    }

    public void removeFromBlacklist(ClientSession clientSession) {
        for(int i= blacklist.size() - 1; i>=0; i--) {
            if(blacklist.get(i).equals(clientSession)) {
                blacklist.remove(i);
            }
        }
    }

    public APIServer getServer() {
        return server;
    }

    public APIServerConfig getServerConfig() {
        return serverConfig;
    }

    public ArrayList<BlacklistEntry> getBlacklist() {
        return blacklist;
    }

    public ArrayList<RemoteClient> getRateLimitedClients() {
        return rateLimitedClients;
    }

    public ArrayList<ClientSession> getClientSessions() {
        return server.getClientSessions();
    }

    private class BlacklistEntry {

        private BlacklistEntryType entryType;
        private String value;

        public BlacklistEntry(BlacklistEntryType entryType, String value) {
            this.entryType = entryType;
            this.value = value;
        }

        public BlacklistEntry(BlacklistEntryType entryType, ClientSession clientSession) {
            this.entryType = entryType;
            switch(entryType) {
                case CLIENT_ID:
                    this.value = clientSession.getSession().getClientId();
                    break;
                case USER_ID:
                    this.value = clientSession.getSession().getUserId();
                    break;
                case API_KEY:
                    this.value = clientSession.getClient().getApiKey();
                    break;
                case IP_ADDRESS:
                    this.value = clientSession.getClient().getClientInfo().getRemoteIp();
                    break;
            }
        }

        public boolean equals(ClientSession clientSession) {
            switch(entryType) {
                case CLIENT_ID:
                    return this.value.equals(clientSession.getSession().getClientId());
                case USER_ID:
                    return this.value.equals(clientSession.getSession().getUserId());
                case API_KEY:
                    return this.value.equals(clientSession.getClient().getApiKey());
                case IP_ADDRESS:
                    return this.value.equals(clientSession.getClient().getClientInfo().getRemoteIp());
            }
            return false;
        }

        public String getValue() {
            return value;
        }

        public BlacklistEntryType getEntryType() {
            return entryType;
        }

    }
    public enum BlacklistEntryType {
        IP_ADDRESS,
        USER_ID,
        CLIENT_ID,
        API_KEY
    }

}
