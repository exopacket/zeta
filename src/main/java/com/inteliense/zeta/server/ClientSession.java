package com.inteliense.zeta.server;

public class ClientSession {

    private RemoteClient client;
    private APISession session;
    private ClientInfo clientInfo;

    public ClientSession(ClientInfo info, APISession session) {
        this.session = session;
        this.clientInfo = info;
    }
    public ClientSession(ClientInfo info, RemoteClient client, APISession session) {
        this.client = client;
        this.session = session;
        this.clientInfo = info;
    }

    public static ClientSession createClient(ClientInfo clientInfo, APIKeyPair apiKeys, APIServer server, boolean isZeroTrust) {

        try {

            APIServerType serverType = server.getConfig().getServerType();
            APISession session = new APISession(apiKeys, clientInfo.getRemoteIp(), serverType,
                    server.getConfig().getMinutesTillInvalid(), isZeroTrust
            );
            ClientSession retVal = new ClientSession(clientInfo, session);

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
                public boolean isAuthenticated(RequestHeaders headers, APIResource resource, Parameters params) {
                    return this.getServer().isAuthenticated(headers, resource, params, retVal);
                }

                @Override
                public boolean lookupUserInfo() {
                    return this.getServer().lookupUserInfo(retVal);
                }

            };

            client.setClientInfo(clientInfo);
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

    public APISession getSession() {
        return session;
    }

    public void newRequest() {
        getSession().newRequest();
        getClient().newRequest();
    }

}