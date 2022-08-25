package com.inteliense.trusty.server;

import com.sun.net.httpserver.Headers;

import java.util.ArrayList;

public abstract class RemoteClient {

    private ArrayList<APISession> sessions;
    private APIServer server;
    private APIKeyPair apiKeys;
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

    public boolean equals(APIKeyPair apiKeys) {
        return getApiKey().equals(apiKeys.getKey());
    }

    public boolean equals(String sessionId) {
        return findSession(sessionId) != null;
    }

    public APISession getSession(String sessionId) {
        return findSession(sessionId);
    }

    public abstract boolean isLimited(int perMinute);

    public abstract boolean inBlacklist();
    //public abstract boolean lookupApiKeys(String apiKey);

    public abstract boolean isAuthenticated(Headers headers, APIResource resource, Parameters params);

    public abstract boolean lookupUserInfo();

    private APISession findSession(String sessionId) {
        for(int i=0; i<sessions.size(); i++) {
            APISession curr = sessions.get(i);
            if(curr.getSessionId().equals(sessionId))
                return curr;
        }
        return null;
    }



}
