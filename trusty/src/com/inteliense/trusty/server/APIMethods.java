package com.inteliense.trusty.server;

import com.sun.net.httpserver.Headers;
import org.json.simple.JSONObject;

import java.security.KeyPair;
import java.util.HashMap;

public interface APIMethods {
    boolean isAuthenticated(Headers headers, APIResource resource, Parameters params, ClientSession clientSession);
    boolean inTimeout(ClientSession clientSession, int perMinute);
    boolean inBlacklist(ClientSession clientSession);
    APIKeyPair lookupApiKey(String apiKey);
    boolean lookupUserInfo(ClientSession session);
    HashMap<String, String> getParameters(String body, ContentType contentType);
    void addToBlacklist(ClientSession clientSession, API.BlacklistEntryType entryType);
    void removeFromBlacklist(ClientSession clientSession);

}
