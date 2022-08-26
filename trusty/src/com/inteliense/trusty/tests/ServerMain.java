package com.inteliense.trusty.tests;

import com.inteliense.trusty.server.*;

import java.security.KeyPair;
import java.util.HashMap;

public class ServerMain {

    public static void main(String[] args) throws APIException {

        APIServerConfig config = new APIServerConfig("127.0.0.1", 8080, "/api");
        config.setApiServerKeyPassword("testing");
        config.setApiServerKeystorePath("/Users/int/testing.keystore");
        config.setServerType(APIServerType.REST);
        config.setRateLimit(25);

        API api = new API(config) {
            @Override
            public APIKeyPair lookupApiKey(String apiKey) {
                return null;
            }
        };

        api.start();

        api.addResource("accounts/login", new String[]{"username", "password"}, new APIResource() {
            @Override
            public APIResponse execute(ClientSession clientSession, Parameters params) {

                //PROCESS accounts/login REQUEST

                return new APIResponse(clientSession, "200-OKAY", ResponseCode.SUCCESSFUL);
            }

        });

    }

}
