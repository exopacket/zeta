package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.JSON;
import com.inteliense.trusty.utils.RSA;
import com.inteliense.trusty.utils.Random;
import com.inteliense.trusty.utils.SHA;
import org.json.simple.JSONObject;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class APIResponse {

    private ResponseCode responseCode;
    private String response;
    private ClientSession clientSession;
    private ContentType contentType;
    private LocalDateTime timestamp;
    private boolean isAsync = false;
    private int pollPeriod = 700;
    private boolean isCompleted = false;
    private AsyncRequest asyncRequest;
    private APIResponse redirectResponse;

    public APIResponse(ClientSession clientSession, String response, ResponseCode responseCode) {

        this.clientSession = clientSession;
        this.response = response;
        this.responseCode = responseCode;

    }

    public APIResponse(ClientSession clientSession, JSONObject responseObj, ResponseCode responseCode) {

        this.clientSession = clientSession;
        this.response = JSON.getString(responseObj);
        this.responseCode = responseCode;

    }

    public APIResponse(ClientSession clientSession, ResponseCode responseCode) {

        this.clientSession = clientSession;
        this.responseCode = responseCode;

    }

    public void encrypt() throws Exception {

        JSONObject obj = new JSONObject();
        String keySetId = clientSession.getSession().getKeySetId();

        String encrypted = RSA.decrypt(
                response, clientSession
                        .getSession()
                        .getClientPublicKey()
                        .getPublicKeyId());

        obj.put("rsa_val", encrypted);
        obj.put("key_set_id", keySetId);

        setResponse(obj);

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
        return (int) Math.round(pollPeriod * 1.5);
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
        return clientSession.getClient();
    }

    public APISession getApiSession() { return clientSession.getSession(); }

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
                        clientSession.getSession().getSessionId()),
                        getClient().getApiKey()));
                dynamicRequestId = hexVal;
            } catch (Exception ex) {
                throw new APIException(ex.getMessage());
            }

        }

    }

}
