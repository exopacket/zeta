package com.inteliense.trusty.server;

public interface ClientFilter {

    boolean isPastRateLimit(ClientSession clientSession, int perMinute);
    boolean inBlacklist(ClientSession clientSession);
    boolean isAuthenticated(RequestHeaders headers, APIResource resource, Parameters params, ClientSession clientSession);
    boolean lookupUserInfo(ClientSession clientSession);

}
