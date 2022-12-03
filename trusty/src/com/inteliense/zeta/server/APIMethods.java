package com.inteliense.zeta.server;

import java.util.HashMap;

public interface APIMethods {
    boolean isAuthenticated(RequestHeaders headers, APIResource resource, Parameters params, ClientSession clientSession);
    boolean inTimeout(ClientSession clientSession, int perMinute);
    boolean inBlacklist(ClientSession clientSession);
    APIKeyPair lookupApiKey(String apiKey);
    boolean lookupUserInfo(ClientSession session);
    HashMap<String, String> getParameters(String body, ContentType contentType);
    void addToBlacklist(ClientSession clientSession, API.BlacklistEntryType entryType);
    void removeFromBlacklist(ClientSession clientSession);

}
