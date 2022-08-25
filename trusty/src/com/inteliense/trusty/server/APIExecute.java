package com.inteliense.trusty.server;

public interface APIExecute {

    APIResponse execute(RemoteClient client, Parameters params);

}
