package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.Hex;
import com.inteliense.trusty.utils.SHA;

import java.time.LocalDateTime;
import java.util.Base64;

public class APISession {

    private String clientId;
    private String userId;
    private String clientDynamicAuth;
    private String sessionId;
    private LocalDateTime started;
    private LocalDateTime lastRequest;

    private int requestCount;

    private ClientInfo info;

    public APISession(String apiKey, String clientId, String userId) throws APIException {

        this.sessionId = createSessionId();
        this.clientDynamicAuth = createInitialDynamicCookie(apiKey);
        this.clientId = clientId;
        this.userId = userId;
        this.started = LocalDateTime.now();
        this.lastRequest = LocalDateTime.now();

    }

    public APISession(String apiKey) throws APIException {

        this.sessionId = createSessionId();
        this.started = LocalDateTime.now();
        this.lastRequest = LocalDateTime.now();

    }

    public LocalDateTime getLastRequest() {
        return lastRequest;
    }

    public LocalDateTime getStarted() {
        return started;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientDynamicAuth() {
        return clientDynamicAuth;
    }

    public void newRequest() {
        requestCount++;
        lastRequest = LocalDateTime.now();
    }
    public String getUserId() {
        return userId;
    }

    public String updateClientAuth(String apiKey) throws APIException {

        try {
            String hexVal = SHA.getSha1(SHA.getHmac256(SHA.getHmac256(clientDynamicAuth, sessionId), apiKey));
            String base64Val = Base64.getEncoder().encodeToString(Hex.fromHex(hexVal));
            this.clientDynamicAuth = base64Val;
            return base64Val;
        } catch (Exception ex) {
            throw new APIException(ex.getMessage());
        }

    }

    private String createSessionId() throws APIException {

        return "";

            /*

            try {
                String hexVal = SHA.getSha1(SHA.getHmac256(SHA.getHmac256(Random.str(128), userId), apiKey));
                String base64Val = Base64.getEncoder().encodeToString(Hex.fromHex(hexVal));
                return base64Val;
            } catch (Exception ex) {
                throw new APIException(ex.getMessage());
            } */

    }

    private String createInitialDynamicCookie(String apiKey) throws APIException {

        try {
            String hexHmac = SHA.getHmac256(this.sessionId, apiKey);
            String hexVal = SHA.get256(Base64.getEncoder().encodeToString(Hex.fromHex(hexHmac)));
            String base64Val = Base64.getEncoder().encodeToString(Hex.fromHex(hexVal));
            return base64Val;
        } catch (Exception ex) {
            throw new APIException(ex.getMessage());
        }

    }

    private boolean verifyInitHash(String hash, String ipAddress, String apiKey) throws APIException {

        try {
            String hexHmac = SHA.getHmac256(ipAddress, apiKey);
            String hexVal = SHA.get256(Base64.getEncoder().encodeToString(Hex.fromHex(hexHmac)));
            String base64Val = Base64.getEncoder().encodeToString(Hex.fromHex(hexVal));
            return base64Val.equals(hash);
        } catch (Exception ex) {
            throw new APIException(ex.getMessage());
        }

    }

}
