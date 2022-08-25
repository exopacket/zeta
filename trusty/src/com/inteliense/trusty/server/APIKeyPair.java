package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.Random;

public class APIKeyPair {

    private String key;
    private String secret;

    private ZeroTrustKeyPairs zeroTrustKeys;

    public APIKeyPair(String key, String secret) {
        this.key = key;
        this.secret = secret;
    }

    public static APIKeyPair generate() {
        return new APIKeyPair(
                Random.str(72, "apikey"),
                Random.str(72, "secret")
        );
    }

    public String getKey() {
        return key;
    }

    public String getSecret() {
        return secret;
    }

}
