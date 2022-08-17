package com.inteliense.trusty.server;

import org.json.simple.JSONObject;

import java.security.KeyPair;
import java.util.HashMap;

public interface APIMethods {

    void addResource(String value, APIResource definition);
    boolean isAuthenticated(RemoteClient client);
    RemoteClient initAuthentication(String apiKey, String ipAddress, String port, String hostname, HashMap<String, String> parameters);

    KeyPair[] getKeyPairs(RemoteClient client);
    boolean isPastRateLimit(RemoteClient client, int perMinute);
    boolean inBlacklist(RemoteClient client);
    boolean lookupApiKey(String apiKeyHeader);
    boolean lookupUserId(String apiKey, String clientId, String userId);
    HashMap<String, String> parseRequestBody(RemoteClient client, String resource, String body);
    HashMap<String, String> decryptZeroTrust(JSONObject obj, ZeroTrustRequestType type);

}
