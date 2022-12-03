package com.inteliense.zeta.server;

public abstract class RemoteClient {

    private APIServer server;
    private APIKeyPair apiKeys;
    private ClientInfo clientInfo;

    public static final RemoteClient NONE = null;

    public RemoteClient(APIKeyPair apiKeys, APIServer server) throws APIException {
        this.server = server;
        this.apiKeys = apiKeys;
    }

    public String getApiKey() {
        return apiKeys.getKey();
    }
    public String getApiSecret() { return apiKeys.getSecret(); }
    public APIServer getServer() {
        return this.server;
    }
    public ClientInfo getClientInfo() {
        return clientInfo;
    }

    public void setClientInfo(ClientInfo clientInfo) {
        this.clientInfo = clientInfo;
    }

    public boolean equals(APIKeyPair apiKeys) {
        return getApiKey().equals(apiKeys.getKey());
    }

    public boolean equals(String remoteIp) {
        return clientInfo.getRemoteIp().equals(this.clientInfo.getRemoteIp());
    }

    public boolean isFlagged(RequestHeaders headers, String hostname) {
        clientInfo.verifyHostname(hostname);
        clientInfo.verifyUserAgent(headers.getString("User-Agent"));
        return clientInfo.isFlagged();
    }

    public void newRequest() {
        clientInfo.incrementIpRequests();
    }

    public abstract boolean isLimited(int perMinute);

    public abstract boolean inBlacklist();

    public abstract boolean isAuthenticated(RequestHeaders headers, APIResource resource, Parameters params);

    public abstract boolean lookupUserInfo();



}
