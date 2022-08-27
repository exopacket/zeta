package com.inteliense.trusty.server;

import java.util.ArrayList;

public class ClientInfo {

    private String remoteIp;
    private ArrayList<String> remoteHostname;
    private ArrayList<String> userAgent;
    private boolean hostnameFlag = false;
    private boolean userAgentFlag = false;
    private int numIpRequests = 0;

    public ClientInfo(RequestHeaders headers, String remoteIp, String remoteHostname) {
        userAgent.add(headers.getString("User-Agent"));
        this.remoteHostname.add(remoteHostname);
        this.remoteIp = remoteIp;
    }

    public boolean verifyHostname(String remoteHostname) {
        boolean res = this.remoteHostname.contains(remoteHostname);
        if(!res) {
            this.remoteHostname.add(remoteHostname);
            hostnameFlag = true;
        }
        return res;
    }

    public boolean verifyUserAgent(String userAgent) {
        boolean res = this.userAgent.contains(userAgent);
        if(!res) {
            this.userAgent.add(userAgent);
            userAgentFlag = true;
        }
        return res;
    }

    public int getNumIpRequests() {
        return numIpRequests;
    }

    public String getLastUserAgent() {
        return userAgent.get(userAgent.size() - 1);
    }

    public String getUserAgent(int index) {
        return userAgent.get(index);
    }

    public int numUserAgentEntries() {
        return userAgent.size();
    }

    public String getRemoteIp() {
        return remoteIp;
    }

    public void incrementIpRequests() {
        numIpRequests++;
    }

    public String getLastHostname() {
        return remoteHostname.get(remoteHostname.size() - 1);
    }

    public String getHostname(int index){
        return remoteHostname.get(index);
    }

    public int numHostnameEntries() {
        return remoteHostname.size();
    }
    public boolean isFlagged() {
        return (hostnameFlag || userAgentFlag);
    }

}
