package com.inteliense.trusty.server;

import org.json.simple.JSONObject;

import java.security.KeyPair;
import java.util.HashMap;

public interface APIMethods {

    APIResource addResource(String value, APIResource definition);
    boolean isAuthenticated(RemoteClient client);
    RemoteClient initializeSession(String apiKey, String ipAddress, String port, String hostname, HashMap<String, String> parameters);
    KeyPair[] getKeyPairs(RemoteClient client);
    boolean isPastRateLimit(RemoteClient client, int perMinute);
    boolean inBlacklist(RemoteClient client);
    APIKeyPair lookupApiKey(String apiKey);
    boolean lookupUserData(String apiKey, String clientId, String userId);
    HashMap<String, String> parseRequestBody(RemoteClient client, String resource, String body);
    HashMap<String, String> decryptZeroTrust(JSONObject obj, ZeroTrustRequestType type);

}
