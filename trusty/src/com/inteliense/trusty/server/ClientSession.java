package com.inteliense.trusty.server;

import com.sun.net.httpserver.Headers;

public class ClientSession {

    private RemoteClient client;
    private APISession session;

    public ClientSession(APISession session) {
        this.session = session;
    }
    public ClientSession(RemoteClient client, APISession session) {
        this.client = client;
        this.session = session;
    }

    public static ClientSession createClient(ClientInfo clientInfo, APIKeyPair apiKeys, APIServer server) {

        try {

            APIServerType serverType = server.getConfig().getServerType();
            APISession session = new APISession(clientInfo, apiKeys, serverType, server.getConfig().getRequestsPerMinute());
            ClientSession retVal = new ClientSession(session);
            RemoteClient client = new RemoteClient(apiKeys, server) {
                @Override
                public boolean isLimited(int perMinute) {
                    return this.getServer().isPastRateLimit(retVal, perMinute);
                }

                @Override
                public boolean inBlacklist() {
                    return this.getServer().inBlacklist(retVal);
                }

                @Override
                public boolean isAuthenticated(Headers headers, APIResource resource, Parameters params) {
                    return this.getServer().isAuthenticated(headers, resource, params, retVal);
                }

                @Override
                public boolean lookupUserInfo() {
                    return this.getServer().lookupUserInfo(retVal);
                }
            };

            retVal.setClient(client);

            return retVal;

        } catch (APIException e) {
            System.out.println(e.getMessage());
        }

        return null;

    }

    public void setClient(RemoteClient client) {
        this.client = client;
    }

    public RemoteClient getClient() {
        return client;
    }

    public APISession getSession () {
        return session;
    }

}