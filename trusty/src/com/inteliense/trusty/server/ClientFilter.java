package com.inteliense.trusty.server;

import com.sun.net.httpserver.Headers;

import java.util.HashMap;

public interface ClientFilter {

    boolean isPastRateLimit(ClientSession clientSession, int perMinute);
    boolean inBlacklist(ClientSession clientSession);
    boolean isAuthenticated(Headers headers, APIResource resource, Parameters params, ClientSession clientSession);
    boolean lookupUserInfo(ClientSession clientSession);

}
