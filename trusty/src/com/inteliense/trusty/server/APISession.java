package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.EncodingUtils;
import com.inteliense.trusty.utils.Random;
import com.inteliense.trusty.utils.SHA;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;

public class APISession {

    private String sessionId;
    private String clientId;
    private String userId;
    private String sessionAuth;
    private byte[] randomBytes;
    private LocalDateTime started;
    private LocalDateTime lastRequest;
    private int requestCount = 0;
    private ClientInfo info;

    private APIServerType serverType;
    private APIKeyPair apiKeys;
    private ZeroTrustKeyPairs zeroTrustKeyPairs;
    private boolean isActive = true;

    private ArrayList<LocalDateTime> recentRequests;
    private int requestsPerMinute = 60;

    public APISession(ClientInfo info, APIKeyPair apiKeys, APIServerType serverType, int requestsPerMinute) throws APIException {

        if(serverType == APIServerType.ZERO_TRUST) {
            this.sessionId = createSessionId();
            this.randomBytes = Random.secure(96);
        }
        this.apiKeys = apiKeys;
        this.started = LocalDateTime.now();
        this.lastRequest = LocalDateTime.now();
        this.info = info;
        this.requestsPerMinute = requestsPerMinute;

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

    public int getRecentRequests() {

        for(int i=recentRequests.size() - 1; i>=0; i--) {
            LocalDateTime limit = LocalDateTime.now().minusMinutes(1);
            if(recentRequests.get(i).isBefore(limit))
                recentRequests.remove(i);
        }

        return recentRequests.size();

    }

    public String getSessionAuth() {
        return sessionAuth;
    }

    public boolean isActive() {
        return isActive;
    }

    public void deactivate() {
        isActive = false;
    }

    public String getRandomBytes() {
        return EncodingUtils.getHex(this.randomBytes);
    }

    public void newRequest() {
        requestCount++;
        lastRequest = LocalDateTime.now();
        recentRequests.add(0, LocalDateTime.now());
    }
    public String getUserId() {
        return userId;
    }

    public String getKeySetId() {
        return zeroTrustKeyPairs.getKeySetId();
    }

    public ZeroTrustKeyPairs.AsymmetricKey getClientPublicKey() {
        return zeroTrustKeyPairs.getClientPublic();
    }

    public ZeroTrustKeyPairs.AsymmetricKey getServerPublicKey() {
        return zeroTrustKeyPairs.getServerPublic();
    }

    public ZeroTrustKeyPairs.AsymmetricKey getClientPrivateKey() {
        return zeroTrustKeyPairs.getClientPrivate();
    }

    public ZeroTrustKeyPairs.AsymmetricKey getServerPrivateKey() {
        return zeroTrustKeyPairs.getServerPrivate();
    }

    public ClientInfo getClientInfo() {
        return info;
    }

    public String updateClientAuth(String apiKey) throws APIException {

        try {
            String hexVal = SHA.getSha1(SHA.getHmac256(SHA.getHmac256(sessionAuth, sessionId), apiKey));
            String base64Val = Base64.getEncoder().encodeToString(EncodingUtils.fromHex(hexVal));
            this.sessionAuth = base64Val;
            return base64Val;
        } catch (Exception ex) {
            throw new APIException(ex.getMessage());
        }

    }

    private String createSessionId() throws APIException {

        String ipAddr = info.getRemoteIp();
        String apiSecret = apiKeys.getSecret();
        String value = ipAddr + ";" + apiSecret;
        return SHA.getSha1(SHA.getHmac384(value, Random.secure(96)));

    }

    private String createInitialSessionAuth(String apiKey) throws APIException {

        return SHA.getHmac384(sessionId, randomBytes);

    }

    private boolean verifyInitHash(String hash, String ipAddress, String apiKey) throws APIException {

        try {
            String hexHmac = SHA.getHmac256(ipAddress, apiKey);
            String hexVal = SHA.get256(Base64.getEncoder().encodeToString(EncodingUtils.fromHex(hexHmac)));
            String base64Val = Base64.getEncoder().encodeToString(EncodingUtils.fromHex(hexVal));
            return base64Val.equals(hash);
        } catch (Exception ex) {
            throw new APIException(ex.getMessage());
        }

    }

}
