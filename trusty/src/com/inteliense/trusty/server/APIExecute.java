package com.inteliense.trusty.server;

public interface APIExecute {

    APIResponse execute(ClientSession clientSession, Parameters params);

}
