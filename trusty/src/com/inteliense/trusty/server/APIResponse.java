package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.JSON;
import com.inteliense.trusty.utils.Random;
import com.inteliense.trusty.utils.SHA;
import org.json.simple.JSONObject;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class APIResponse {

    private ResponseCode responseCode;
    private String response;
    private RemoteClient client;
    private ContentType contentType;
    private LocalDateTime timestamp;

    private boolean isAsync = false;
    private int pollPeriod = 700;
    private boolean isCompleted = false;
    private AsyncRequest asyncRequest;
    private APIResponse redirectResponse;

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

    public ContentType getContentType() {
        return contentType;
    }

    public void setContentType(ContentType type) {
        contentType = type;
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

    public boolean isCompleted() {
        return isCompleted;
    }

    public void markCompleted() {
        isCompleted = true;
    }

    public boolean isAsync() {
        return isAsync;
    }

    public ResponseCode getResponseCode() throws APIException {
        return responseCode;
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

    public APIResponse getRedirectResponse() {
        return redirectResponse;
    }

    public AsyncRequest getAsyncRequest() {
        return asyncRequest;
    }

    public class AsyncRequest {

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
