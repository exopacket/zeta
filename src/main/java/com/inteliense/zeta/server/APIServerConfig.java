package com.inteliense.zeta.server;

import java.net.InetSocketAddress;

public final class APIServerConfig {

    private int apiPort;
    private int responsePort = 8080;
    private int requestsPerMinute = 60;
    private String bindAddress = "";
    private APIServerType serverType = APIServerType.REST;

    private APIServerType serverResponseType = APIServerType.REST_SYNC;
    private String apiServerKeyPassword = null;
    private String responseServerKeyPassword = null;
    private String apiServerKeystorePath = null;
    private String responseServerKeystorePath = null;
    private String apiPath = "/api";
    private String responseServerPath = "/response";
    private int maxSessions = 0;
    private int minutesTillInvalid = 30;
    private boolean useDynamicApiKey = false;
    private CORSPolicy corsPolicy;
    private String[] zeroTrustSessionPaths = new String[]{"session/init", "session/keys", "session/close"};

    public APIServerConfig(int port) {
        this.apiPort = port;
        this.bindAddress = "";
        this.corsPolicy = new CORSPolicy(false);
    }

    public APIServerConfig(String bindAddress, int port) {
        this.bindAddress = bindAddress;
        this.apiPort = port;
        this.corsPolicy = new CORSPolicy(false);
    }

    public APIServerConfig(int port, String serverPath) {
        this.apiPort = port;
        this.bindAddress = "";
        setApiPath(serverPath);
        this.corsPolicy = new CORSPolicy(false);

    }

    public APIServerConfig(String bindAddress, int port, String serverPath) {
        this.bindAddress = bindAddress;
        this.apiPort = port;
        setApiPath(serverPath);
        this.corsPolicy = new CORSPolicy(false);
    }

    public APIServerConfig useDynamicApiKey(boolean val) {
        useDynamicApiKey = val;
        return this;
    }

    public APIServerConfig setSessionResourcePaths(String sessionInitPath, String sessionKeyTransferPath, String sessionClosePath) {
        zeroTrustSessionPaths[0] = sessionInitPath;
        zeroTrustSessionPaths[1] = sessionKeyTransferPath;
        zeroTrustSessionPaths[2] = sessionClosePath;
        return this;
    }

    public APIServerConfig setResponsePort(int port) {

        responsePort = port;
        return this;

    }
    public APIServerConfig setResponseServerPath(String responseServerPath) {
        this.responseServerPath = responseServerPath;
        return this;
    }

    public APIServerConfig setServerResponseType(APIServerType serverResponseType) {
        this.serverResponseType = serverResponseType;
        return this;
    }

    public APIServerConfig setRequestsPerMinute(int requestsPerMinute) {

        this.requestsPerMinute = requestsPerMinute;
        return this;

    }

    public APIServerConfig setResponseServerKeyPassword(String keyPassword) {
        this.responseServerKeyPassword = keyPassword;
        return this;
    }

    public APIServerConfig setApiServerKeyPassword(String keyPassword) {

        this.apiServerKeyPassword = keyPassword;
        return this;

    }

    public APIServerConfig setServerType(APIServerType serverType) {
        this.serverType = serverType;
        return this;
    }

    public APIServerConfig setRateLimit(int requestsPerSecond) {

        this.requestsPerMinute = requestsPerSecond;
        return this;

    }

    public APIServerConfig setMinutesTillInvalid(int minutesTillInvalid) {

        this.minutesTillInvalid = minutesTillInvalid;
        return this;

    }

    public APIServerConfig setCorsPolicy(CORSPolicy policy) {
        corsPolicy = policy;
        return this;
    }

    public APIServerConfig setApiPath(String apiPath) {

        if (apiPath.charAt(apiPath.length() - 1) == '/') {
            this.apiPath = apiPath.substring(0, apiPath.length() - 1);
        } else {
            this.apiPath = apiPath;
        }

        return this;

    }

    public APIServerConfig setApiServerKeystorePath(String keystorePath) {
        this.apiServerKeystorePath = keystorePath;
        return this;
    }

    public APIServerConfig setResponseServerKeystorePath(String keystorePath) {
        this.responseServerKeystorePath = keystorePath;
        return this;
    }

    public APIServerConfig setMaxSessions(int val) {
        this.maxSessions = val;
        return this;
    }

    public String[] getZeroTrustSessionPaths() {
        return zeroTrustSessionPaths;
    }

    public InetSocketAddress getBindAddress() {
        return (bindAddress.equals("")) ?
                new InetSocketAddress(this.apiPort) :
                new InetSocketAddress(this.bindAddress, this.apiPort);
    }

    public String getApiServerKeystorePath() {
        return apiServerKeystorePath;
    }

    public String getApiServerKeyPassword() {
        return apiServerKeyPassword;
    }

    public String getResponseServerKeystorePath() {

        return (responseServerKeystorePath == null) ? apiServerKeystorePath : responseServerKeystorePath;

    }

    public boolean useDynamicApiKey() {
        return useDynamicApiKey;
    }

    public int getMinutesTillInvalid() {
        return minutesTillInvalid;
    }

    public String getResponseServerKeyPassword() {

        return (responseServerKeyPassword == null) ? apiServerKeyPassword : responseServerKeyPassword;

    }

    public CORSPolicy getCorsPolicy() {
        return this.corsPolicy;
    }

    public int getApiPort() {
        return apiPort;
    }

    public int getResponsePort() {
        return responsePort;
    }

    public int getRequestsPerMinute() {
        return requestsPerMinute;
    }


    public String getResponseServerPath() {
        return responseServerPath;
    }

    public int getRateLimit() {
        return requestsPerMinute;
    }

    public int getMaxSessions() {
        return maxSessions;
    }

    public String getApiPath() {
        return this.apiPath;
    }

    public APIServerType getServerType() {
        return serverType;
    }

    public APIServerType getServerResponseType() { return serverResponseType; }

}
