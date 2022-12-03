package com.inteliense.zeta.server;

public class RESTfulAPI extends API {

    public RESTfulAPI(APIServerConfig config) throws APIException {
        super(config);
    }

    public static RESTfulAPI fromDefault(String keystorePath, String keystorePassword) throws APIException {

        APIServerConfig config = new APIServerConfig(443, "/api")
                .setServerType(APIServerType.REST)
                .setServerResponseType(APIServerType.REST_SYNC)
                .setMaxSessions(10)
                .setMinutesTillInvalid(15)
                .setResponseServerPath("/response")
                .setResponsePort(8080)
                .setRateLimit(60)
                .setApiServerKeystorePath(keystorePath)
                .setResponseServerKeystorePath(keystorePath)
                .setApiServerKeyPassword(keystorePassword)
                .setResponseServerKeyPassword(keystorePassword);

        CORSPolicy corsPolicy = new CORSPolicy(false);
        config.setCorsPolicy(corsPolicy);

        return new RESTfulAPI(config);

    }

    public static RESTfulAPI asyncServer(String keystorePath, String keystorePassword, boolean corsPermitted) throws APIException {

        APIServerConfig config = new APIServerConfig(443, "/api")
                .setServerType(APIServerType.REST)
                .setServerResponseType(APIServerType.REST_SYNC)
                .setMaxSessions(10)
                .setMinutesTillInvalid(15)
                .setRateLimit(60)
                .setApiServerKeystorePath(keystorePath)
                .setApiServerKeyPassword(keystorePassword);

        config.setResponseServerPath("/responses")
                    .setResponsePort(8080)
                    .setResponseServerKeystorePath(keystorePath)
                    .setResponseServerKeyPassword(keystorePassword);



        CORSPolicy corsPolicy = new CORSPolicy(corsPermitted);

        if(corsPermitted) {
            String[] headers = new String[]{"Origin", "X-Requested-With",
                    "Content-Type", "Accept",
                    "X-Api-Key", "X-Request-Timestamp", "X-Request-Signature",
            };
            corsPolicy.setHeaders(headers);
        }

        config.setCorsPolicy(corsPolicy);

        return new RESTfulAPI(config);

    }

    public static RESTfulAPI withCORS(String keystorePath, String keystorePassword) throws APIException {

        APIServerConfig config = new APIServerConfig(443, "/api")
                .setServerType(APIServerType.REST)
                .setServerResponseType(APIServerType.REST_SYNC)
                .setMaxSessions(10)
                .setMinutesTillInvalid(15)
                .setRateLimit(60)
                .setApiServerKeystorePath(keystorePath)
                .setApiServerKeyPassword(keystorePassword);

        String[] headers = new String[]{"Origin", "X-Requested-With",
                "Content-Type", "Accept",
                "X-Api-Key", "X-Request-Timestamp", "X-Request-Signature",
        };

        CORSPolicy corsPolicy = new CORSPolicy(true);
        corsPolicy.setHeaders(headers);

        config.setCorsPolicy(corsPolicy);

        return new RESTfulAPI(config);

    }

    public static RESTfulAPI withCORS(String keystorePath, String keystorePassword, APIServerType responseServerType) throws APIException {

        APIServerConfig config = new APIServerConfig(443, "/api")
                .setServerType(APIServerType.REST)
                .setServerResponseType(APIServerType.REST_SYNC)
                .setMaxSessions(10)
                .setMinutesTillInvalid(15)
                .setRateLimit(60)
                .setApiServerKeystorePath(keystorePath)
                .setApiServerKeyPassword(keystorePassword);

        if(responseServerType == APIServerType.REST_HYBRID || responseServerType == APIServerType.REST_ASYNC) {
            config.setResponseServerPath("/responses")
                    .setResponsePort(8080)
                    .setResponseServerKeystorePath(keystorePath)
                    .setResponseServerKeyPassword(keystorePassword);
        }

        String[] headers = new String[]{"Origin", "X-Requested-With",
                "Content-Type", "Accept",
                "X-Api-Key", "X-Request-Timestamp", "X-Request-Signature",
        };

        CORSPolicy corsPolicy = new CORSPolicy(true);
        corsPolicy.setHeaders(headers);

        config.setCorsPolicy(corsPolicy);

        return new RESTfulAPI(config);

    }

    @Override
    public APIKeyPair lookupApiKey(String apiKey) {
        return null;
    }
}