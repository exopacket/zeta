package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.Hex;
import com.inteliense.trusty.utils.Random;
import com.inteliense.trusty.utils.SHA;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;

public abstract class RemoteClient {

    private String remoteIp;
    private String remotePort;
    private String remoteHostname;
    private String clientId;
    private HashMap<String, String> credentialData = new HashMap<>();
    private String apiKey;
    private Session session;
    private APIServer server;

    private String clientDigest;

    private ZeroTrustKeyPairs keys;

    public static final RemoteClient NONE = null;

    public RemoteClient(String remoteIp, String remotePort, String remoteHostname, String apiKeyHeader, APIServer server) throws APIException {
        this.remoteIp = remoteIp;
        this.remotePort = remotePort;
        this.remoteHostname = remoteHostname;
        this.server = server;
        this.apiKey = (lookupApiKey(apiKeyHeader)) ? apiKey : null;
        this.session = new Session(apiKey);

    }

    public RemoteClient(String remoteIp, String remotePort, String remoteHostname,
                        String apiKeyHeader, String clientId, String userId,
                        APIServer server) throws APIException {
        this.remoteIp = remoteIp;
        this.remotePort = remotePort;
        this.remoteHostname = remoteHostname;
        this.clientId = clientId;
        this.server = server;
        this.clientDigest = getClientDigest(remoteIp, remoteHostname);
        this.session = new Session(apiKey, clientId, userId);
        this.apiKey = apiKeyHeader;
    }

    private String getClientDigest(String remoteIp, String remoteHostname) {

        return SHA.get512( remoteHostname + "//" + remoteIp);

    }

    public APIServer getServer() {
        return this.server;
    }
    public abstract boolean isLimited(int perMinute);

    public abstract boolean inBlacklist();

    public abstract boolean isAuthenticated();

    public abstract boolean lookupApiKey(String apiKeyHeader);

    public abstract boolean lookupUserId(String apiKey, String clientId, String userId);

    public void addCredentialData(HashMap<String, String> credentials) {
        credentialData = credentials;
    }

    public String getCredential(String key) {

        return credentialData.get(key);

    }

    public String updateClientAuth() throws APIException {

        return session.updateClientAuth(this.apiKey);

    }

    public String getSessionId() {
        return session.getSessionId();
    }

    public String getAuthCookie() {
        return session.getClientDynamicAuth();
    }

    public String getClientId() {
        return clientId;
    }

    public String getUserId() {
        return session.getUserId();
    }


    public String getRemoteIp() {
        return remoteIp;
    }

    public String getRemoteHostname() {
        return remoteHostname;
    }

    public String getRemotePort() {
        return remotePort;
    }

    public String getApiKey() {
        return apiKey;
    }

    public HashMap<String, String> getCredentialData() {
        return credentialData;
    }

    private class Session {

        private String clientId;
        private String userId;
        private String clientDynamicAuth;
        private String sessionId;
        private LocalDateTime started;
        private LocalDateTime lastRequest;

        public Session(String apiKey, String clientId, String userId) throws APIException {

            this.sessionId = createSessionId();
            this.clientDynamicAuth = createInitialDynamicCookie(apiKey);
            this.clientId = clientId;
            this.userId = userId;
            this.started = LocalDateTime.now();
            this.lastRequest = LocalDateTime.now();

        }

        public Session(String apiKey) throws APIException {

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

            try {
                String hexVal = SHA.getSha1(SHA.getHmac256(SHA.getHmac256(Random.str(128), userId), apiKey));
                String base64Val = Base64.getEncoder().encodeToString(Hex.fromHex(hexVal));
                return base64Val;
            } catch (Exception ex) {
                throw new APIException(ex.getMessage());
            }

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

}
