package com.inteliense.trusty.tests;

import com.inteliense.trusty.server.*;
import com.sun.net.httpserver.Headers;
import org.json.simple.JSONObject;

public class ServerMain {

    public static void main(String[] args) throws APIException {

        APIServerConfig config = new APIServerConfig("127.0.0.1", 8080, "/api");
        config.setApiServerKeyPassword("testing");
        config.setApiServerKeystorePath("/Users/int/testing.keystore");
        config.setServerType(APIServerType.ZERO_TRUST_ASYNC);
        config.setRateLimit(25);
        config.useDynamicApiKey(true);

        APIKeyPair testKeyPair = APIKeyPair.generateNewPair();
        final String API_KEY = testKeyPair.getKey();
        final String API_SECRET = testKeyPair.getSecret();
        System.out.println("API KEY = " + API_KEY);
        System.out.println("SECRET = " + API_SECRET);

        API api = new API(config) {

            @Override
            public APIKeyPair lookupApiKey(String apiKey) {

                if(apiKey.equals(API_KEY)) {
                    return new APIKeyPair(API_KEY, API_SECRET);
                }

                return null;

            }

        };

        api.start();

        api.addResource("query/new", new String[]{"sql", "parameters"}, new APIResource() {
            @Override
            public APIResponse execute(ClientSession clientSession, Parameters params, RequestHeaders headers) {

                if(params.getString("sql").equals("SQL") && params.getString("parameters").equals("PARAMS")) {

                    JSONObject obj = new JSONObject();
                    obj.put("response", "RESPONSE");

                    return new APIResponse(clientSession, obj, ResponseCode.SUCCESSFUL);

                }

                return new APIResponse(clientSession, "", ResponseCode.REQUEST_FAILED);
            }

        });

    }

}
