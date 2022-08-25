package com.inteliense.trusty.server;

import java.io.File;

public class APIResponseServer {

    private APIServerConfig config;

    public APIResponseServer(APIServerConfig config) throws APIException {

        this.config = config;

        if(config.getResponseServerKeyPassword().equals("")) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The keystore password is not set.");
        }

        if(config.getResponseServerKeystorePath().equals("")) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The keystore path is not set.");
        }

        if(config.getApiPath().equals("")) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The API path is not set.");
        }

        File tmpFile = new File(config.getResponseServerKeystorePath());

        if(!tmpFile.exists()) {
            throw new APIException("Response Server could not be started successfully. " +
                    "The keystore doesn't exist at " + config.getResponseServerKeystorePath());
        }

        tmpFile = null;

    }
    public void addRequest(ClientSession clientSession,
                           Parameters body, APIResource resource, APIResponse response) {

    }

}
