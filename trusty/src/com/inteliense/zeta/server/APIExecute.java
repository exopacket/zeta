package com.inteliense.zeta.server;


public interface APIExecute {
    APIResponse execute(ClientSession clientSession, Parameters params, RequestHeaders headers) throws Exception;

}
