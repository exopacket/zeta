package com.inteliense.trusty.server;

public class ZeroTrustAPI extends API {
    public ZeroTrustAPI(APIServerConfig config) throws APIException {
        super(config);
    }

    public static ZeroTrustAPI fromDefault(String keystorePath, String keystorePassword) throws APIException {

        APIServerConfig config = new APIServerConfig(8080, "/api")
                .setServerType(APIServerType.ZERO_TRUST)
                .setServerResponseType(APIServerType.ZERO_TRUST_HYBRID)
                .useDynamicApiKey(true)
                .setMaxSessions(3)
                .setMinutesTillInvalid(5)
                .setResponseServerPath("/response")
                .setSessionResourcePaths("session/init", "session/keys", "session/close")
                .setResponsePort(8181)
                .setRateLimit(60)
                .setApiServerKeystorePath(keystorePath)
                .setResponseServerKeystorePath(keystorePath)
                .setApiServerKeyPassword(keystorePassword)
                .setResponseServerKeyPassword(keystorePassword);

        CORSPolicy corsPolicy = new CORSPolicy(false);
        config.setCorsPolicy(corsPolicy);

        return new ZeroTrustAPI(config);
    }

    @Override
    public APIKeyPair lookupApiKey(String apiKey) {
        return null;
    }

}