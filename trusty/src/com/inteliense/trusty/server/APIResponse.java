package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.JSON;
import com.inteliense.trusty.utils.Random;
import com.inteliense.trusty.utils.SHA;
import org.json.simple.JSONObject;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class APIResponse {

    private ResponseCode responseCode;
    private ResponseCode redirectResponseCode;
    private String response;
    private String redirectResponse;
    private RemoteClient client;
    private String requestId;
    private LocalDateTime timestamp;
    private int pollPeriod = 1000;
    private boolean isCompleted = false;
    private boolean authSuccessful = false;

    private AsyncRequest asyncRequest;

    public APIResponse(RemoteClient client, String response, ResponseCode responseCode) {

        this.client = client;
        this.response = response;
        this.responseCode = responseCode;

    }

    public APIResponse(RemoteClient client, JSONObject responseObj, ResponseCode responseCode) {

        this.client = client;
        this.response = JSON.getString(responseObj);
        this.responseCode = responseCode;

    }

    public APIResponse(RemoteClient client, ResponseCode responseCode) {

        this.client = client;
        this.responseCode = responseCode;

    }

    public APIResponse(RemoteClient client, String respServerUrl, boolean isZeroTrust) throws APIException {

        this.client = client;
        this.responseCode = ResponseCode.REDIRECT_START;
        this.redirectResponseCode = ResponseCode.SUCCESSFUL;

        JSONObject obj = new JSONObject();

        timestamp = LocalDateTime.now();

        asyncRequest = (isZeroTrust) ?
                new AsyncRequest(timestamp, client.getAuthCookie()) :
                new AsyncRequest(timestamp);

        respServerUrl = (respServerUrl.charAt(respServerUrl.length() - 1) == '/') ?
                respServerUrl : respServerUrl.substring(0, respServerUrl.length() - 1);

        obj.put("timestamp", timestamp.toEpochSecond(ZoneOffset.UTC));
        obj.put("poll_period", pollPeriod);
        obj.put("request_auth", asyncRequest.getStaticAuthCookie());
        obj.put("response_url", respServerUrl + asyncRequest.getDynamicRequestId());

        this.redirectResponse = JSON.getString(obj);

    }

    public boolean authIsSuccessful() {
        return authSuccessful;
    }

    public void setCompleted(boolean completed) {
        isCompleted = completed;
    }

    public boolean isCompleted() {
        return isCompleted;
    }

    public int getPollPeriod(boolean update) {
        int period = pollPeriod;
        if(update) nextPollPeriod();
        return period;
    }

    private int nextPollPeriod() {
        return (int) Math.round(pollPeriod * 1.35);
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp() {
        this.timestamp = LocalDateTime.now();
    }

    public void setResponseCode(ResponseCode responseCode) {
        this.responseCode = responseCode;
    }

    public ResponseCode getResponseCode() throws APIException {

        ResponseCode code;

        if(responseCode == ResponseCode.REDIRECT_START) {
            code = ResponseCode.REDIRECT_CONTINUE;
        } else if (responseCode == ResponseCode.REDIRECT_CONTINUE && isCompleted) {
            throw new APIException("Async Request response code not set.");
        } else {
            code = responseCode;
        }

        return code;
    }

    public ResponseCode getRedirectResponseCode() {
        return redirectResponseCode;
    }

    public String getRequestId() {
        return requestId;
    }

    public RemoteClient getClient() {
        return client;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public void setResponse(JSONObject obj) throws Exception {
        this.response = JSON.getString(obj);
    }

    public String getResponse() {
        return response;
    }

    public String getRedirectResponse() {
        return redirectResponse;
    }

    private class AsyncRequest {

        private LocalDateTime lastTimestamp;
        private String staticAuthCookie;
        private String dynamicRequestId;

        public AsyncRequest(LocalDateTime lastTimestamp, String staticAuthCookie) throws APIException {

            this.lastTimestamp = lastTimestamp;
            this.staticAuthCookie = staticAuthCookie;
            this.dynamicRequestId = staticAuthCookie;
            getNewRequestId();

        }

        public AsyncRequest(LocalDateTime lastTimestamp) throws APIException {

            this.lastTimestamp = lastTimestamp;
            this.staticAuthCookie = getClient().getApiKey();
            this.dynamicRequestId = Random.str(64);
            getNewRequestId();

        }

        public String getDynamicRequestId() {
            return dynamicRequestId;
        }

        public String getStaticAuthCookie() {
            return staticAuthCookie;
        }

        public boolean authCookieVerifies(String staticAuthCookie) {
            return this.staticAuthCookie.equals(staticAuthCookie);
        }

        public boolean requestIdVerifies(String dynamicRequestId, boolean update) throws APIException {
            boolean retVal = this.dynamicRequestId.equals(dynamicRequestId);
            if(retVal && update) {
                getNewRequestId();
            }
            return retVal;
        }

        public void getNewRequestId() throws APIException {

            try {
                String hexVal = SHA.getSha1(SHA.getHmac256(SHA.getHmac256(
                        dynamicRequestId,
                        getClient().getSessionId()),
                        getClient().getApiKey()));
                dynamicRequestId = hexVal;
            } catch (Exception ex) {
                throw new APIException(ex.getMessage());
            }

        }

    }

}
