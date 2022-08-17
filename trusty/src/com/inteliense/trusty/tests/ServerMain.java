package com.inteliense.trusty.tests;

import com.inteliense.trusty.server.*;

import java.security.KeyPair;
import java.util.HashMap;

public class ServerMain {

    public static void main(String[] args) throws APIException {

        APIServerConfig config = new APIServerConfig("127.0.0.1", 8080, "/api");
        config.setApiServerKeyPassword("testing");
        config.setApiServerKeystorePath("/Users/int/testing.keystore");
        config.setServerType(APIServerType.REST_SYNC);
        config.setRateLimit(25);

        API api = new API(config) {
            @Override
            public KeyPair[] getKeyPairs(RemoteClient client) {
                return null;
            }

            @Override
            public boolean lookupApiKey(String apiKeyHeader) {
                return false;
            }
        };

        api.start();

        api.addResource("testing", new APIResource() {
            @Override
            public APIResponse execute(RemoteClient client, HashMap<String, String> parameters) {
                return new APIResponse(client, "200 - OKAY", ResponseCode.SUCCESSFUL);
            }
        });

    }

}
