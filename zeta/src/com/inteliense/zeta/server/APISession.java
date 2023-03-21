package com.inteliense.zeta.server;

import com.inteliense.zeta.utils.EncodingUtils;
import com.inteliense.zeta.utils.Random;
import com.inteliense.zeta.utils.SHA;

import java.time.LocalDateTime;
import java.util.ArrayList;

public class APISession {

    private String sessionId;
    private String clientId;
    private String userId;
    private String sessionAuth;

    private String signingKey;
    private byte[] randomBytes;
    private LocalDateTime started;
    private LocalDateTime lastRequest;
    private int requestCount = 0;
    private APIKeyPair apiKeys;
    private ZeroTrustKeyPairs zeroTrustKeyPairs;
    private boolean isActive = true;
    private ArrayList<LocalDateTime> recentRequests = new ArrayList<LocalDateTime>();
    private int minutesTillInvalid = 30;

    public APISession(APIKeyPair apiKeys, String ipAddr, APIServerType serverType, int minutesTillInvalid, boolean isZeroTrust) throws APIException {

        this.apiKeys = apiKeys;
        this.started = LocalDateTime.now();
        this.lastRequest = LocalDateTime.now();
        this.minutesTillInvalid = minutesTillInvalid;

        if(isZeroTrust) {
            this.sessionId = createSessionId(ipAddr);
            this.randomBytes = Random.secure(96);
            this.sessionAuth = createInitialSessionAuth();
        }

    }

    public APIKeyPair getApiKeys() {
        return apiKeys;
    }

    public LocalDateTime getLastRequestDateTime() {
        return lastRequest;
    }

    public LocalDateTime getStartedDateTime() {
        return started;
    }
    public String getClientId() {
        return clientId;
    }
    public String getSessionId() {
        return sessionId;
    }
    public boolean invalidateByTime() {

        LocalDateTime limit = lastRequest.plusMinutes(minutesTillInvalid);
        if(LocalDateTime.now().isAfter(limit)) {
            deactivate();
            return true;
        }

        return false;

    }

    public int getRecentRequests() {

        for(int i=recentRequests.size() - 1; i>=0; i--) {
            LocalDateTime limit = LocalDateTime.now().minusMinutes(1);
            if(recentRequests.get(i).isBefore(limit))
                recentRequests.remove(i);
        }

        return recentRequests.size();

    }

    public String getDynamicSessionAuth() {
        return sessionAuth;
    }

    public boolean checkDynamicSessionAuth(String received) {
        String hmac = SHA.getHmac384(getDynamicSessionAuth(), randomBytes);
        boolean res = hmac.equals(received);
        if(res)
            this.sessionAuth = SHA.get384(hmac);
        return res;
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

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public int getRequestCount() {
        return requestCount;
    }

    public void setApiKeys(APIKeyPair apiKeys) {
        this.apiKeys = apiKeys;
    }

    public String getKeySetId() {
        return zeroTrustKeyPairs.getKeySetId();
    }

    public void keysTransferred() {
        zeroTrustKeyPairs.clear();
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

    private String createSessionId(String ipAddr) throws APIException {

        String apiSecret = apiKeys.getSecret();
        String value = ipAddr + ";" + apiSecret;
        return SHA.getSha1(SHA.getHmac384(value, Random.secure(96)));

    }

    private String createInitialSessionAuth() throws APIException {

        return SHA.getHmac384(sessionId, randomBytes);

    }

}
