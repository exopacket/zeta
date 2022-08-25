package com.inteliense.trusty.server;

import java.net.InetSocketAddress;

public class APIServerConfig {

    private int apiPort;
    private int responsePort;
    private int requestsPerMinute = 60;
    private String bindAddress;
    private APIServerType serverType = APIServerType.REST;
    private String apiServerKeyPassword;
    private String responseServerKeyPassword;
    private String apiServerKeystorePath;
    private String responseServerKeystorePath;
    private String apiPath = "/";
    private String responseServerPath = "/";
    private int maxSessions = 0;
    private String sessionClosePath = "";
    private String sessionInitPath = "";
    private String sessionKeyTransferPath = "";

    private APIResources apiResources;
    private CORSPolicy corsPolicy;
    private String[] zeroTrustSessionPaths = new String[]{".", ".", "."};

    public APIServerConfig(int port) {
        this.apiPort = port;
        this.bindAddress = "";
    }

    public APIServerConfig(String bindAddress, int port) {
        this.bindAddress = bindAddress;
        this.apiPort = port;
    }

    public APIServerConfig(int port, String serverPath) {
        this.apiPort = port;
        this.bindAddress = "";
        setApiPath(serverPath);
    }

    public APIServerConfig(String bindAddress, int port, String serverPath) {
        this.bindAddress = bindAddress;
        this.apiPort = port;
        setApiPath(serverPath);
    }

    public static APIServerConfig zeroTrustDefault() {
        return null;
    }

    public String getSessionClosePath() {
        return sessionClosePath;
    }

    public String getSessionInitPath() {
        return sessionInitPath;
    }

    public String getSessionKeyTransferPath() {
        return sessionKeyTransferPath;
    }

    public void setSessionResourcePaths(String sessionInitPath, String sessionKeyTransferPath, String sessionClosePath) {
        this.sessionInitPath = sessionInitPath;
        this.sessionKeyTransferPath = sessionKeyTransferPath;
        this.sessionClosePath = sessionClosePath;
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

    public String getResponseServerKeyPassword() {

        return (responseServerKeyPassword == null) ? apiServerKeyPassword : responseServerKeyPassword;

    }

    public CORSPolicy getCorsPolicy() {
        return this.corsPolicy;
    }

    public void setCorsPolicy(CORSPolicy policy) {
        corsPolicy = policy;
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

    public void setApiServerKeystorePath(String keystorePath) {
        this.apiServerKeystorePath = keystorePath;
    }

    public void setResponseServerKeystorePath(String keystorePath) {
        this.responseServerKeystorePath = keystorePath;
    }

    public void setMaxSessions(int val) {
        this.maxSessions = val;
    }

    public int getMaxSessions() {
        return maxSessions;
    }

    public void setApiPath(String apiPath) {

        if (apiPath.charAt(apiPath.length() - 1) == '/') {
            this.apiPath = apiPath.substring(0, apiPath.length() - 1);
        } else {
            this.apiPath = apiPath;
        }
    }

    public String getApiPath() {
        return this.apiPath;
    }

    public void setResponseServerKeyPassword(String keyPassword) {
        this.responseServerKeyPassword = keyPassword;
    }

    public void setApiServerKeyPassword(String keyPassword) {
        this.apiServerKeyPassword = keyPassword;
    }

    public void setServerType(APIServerType serverType) {
        this.serverType = serverType;
    }

    public void setRateLimit(int requestsPerSecond) {
        this.requestsPerMinute = requestsPerSecond;
    }

    public APIServerType getServerType() {
        return serverType;
    }

}
