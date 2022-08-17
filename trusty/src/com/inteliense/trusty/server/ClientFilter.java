package com.inteliense.trusty.server;

import java.util.HashMap;

public interface ClientFilter {

    boolean isPastRateLimit(RemoteClient client, int perMinute);
    boolean inBlacklist(RemoteClient client);
    boolean isAuthenticated(RemoteClient client);
    RemoteClient initAuthentication(String apiKey, String ipAddress,
                                    String port, String hostname,
                                    HashMap<String, String> parameters);
    boolean lookupApiKey(String apiKeyHeader);
    boolean lookupUserId(String apiKey, String clientId, String userId);

}
