package com.inteliense.trusty.server;

import com.sun.net.httpserver.Headers;

import java.util.HashMap;

public interface ClientFilter {

    boolean isPastRateLimit(RemoteClient client, int perMinute);
    boolean inBlacklist(RemoteClient client);
    boolean isAuthenticated(Headers headers, APIResource resource, Parameters params, RemoteClient client);
    boolean lookupUserInfo(RemoteClient client);

}
