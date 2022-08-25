package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.Hex;
import com.inteliense.trusty.utils.Random;
import com.inteliense.trusty.utils.SHA;
import com.sun.net.httpserver.Headers;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

public abstract class RemoteClient {

    private ArrayList<APISession> sessions;
    private APIServer server;
    private APIKeyPair apiKeys;
    public static final RemoteClient NONE = null;

    public RemoteClient(ClientInfo clientInfo, APIKeyPair apiKeys, APIServer server) throws APIException {
        this.server = server;
        this.apiKeys = apiKeys;
    }

    public RemoteClient(ClientInfo clientInfo, APIKeyPair apiKeys, String sessionId, APIServer server) throws APIException {
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

    public void newRequest() {
        sessions.get(sessions.size() - 1).newRequest();
    }

    public void newRequest(String sessionId) {
        APISession res = findSession(sessionId);
        if(res != null) {
            res.newRequest();
        }
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
