package com.inteliense.zeta.server;

import com.inteliense.zeta.utils.*;
import org.json.simple.JSONObject;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class APIResponse {

    private ResponseCode responseCode;
    private String response;
    private ClientSession clientSession;
    private ContentType contentType = ContentType.JSON;
    private LocalDateTime timestamp;
    private boolean isAsync = false;
    private boolean isCompleted = false;
    private AsyncRequest asyncRequest;

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

        if(responseCode == ResponseCode.REDIRECT_START) {

            String sessionAuth = clientSession.getSession().getDynamicSessionAuth();
            String timestamp = "" + LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
            String value = sessionAuth + ";" + timestamp;
            String apiKey = clientSession.getSession().getApiKeys().getKey();
            String secretKey = clientSession.getSession().getApiKeys().getSecret();
            String authValue = value + ";" + secretKey;

            String staticResponseId = SHA.getHmac384(value, apiKey);
            String initialRequestAuth = SHA.get384(SHA.getHmac384(authValue, apiKey));
            int perMinute = clientSession.getClient().getServer().getConfig().getRequestsPerMinute();

            asyncRequest =
                    new AsyncRequest(
                            clientSession, LocalDateTime.now(),
                            staticResponseId, initialRequestAuth, perMinute);

            this.clientSession = clientSession;
            this.responseCode = ResponseCode.SUCCESSFUL;

            JSONObject obj = new JSONObject();

            obj.put("request_status", "redirect");
            obj.put("response_id", staticResponseId);
            obj.put("initial_auth", initialRequestAuth);
            obj.put("poll_rate", asyncRequest.getPollRate());

            this.response = JSON.getString(obj);

        } else {

            this.clientSession = clientSession;
            this.responseCode = responseCode;

        }

    }

    public void encrypt() throws Exception {

        String encrypted = RSA.encrypt(
                response, clientSession
                        .getSession()
                        .getClientPublicKey()
                        .getPublicKey());

        setResponse("{" + encrypted + "}");

    }

    public ContentType getContentType() {
        return contentType;
    }

    public void setContentType(ContentType type) {
        contentType = type;
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
    public AsyncRequest getAsyncRequest() {
        return asyncRequest;
    }

    public static APIResponse getContinue(ClientSession clientSession, String requestId, String dynamicAuth, int pollRate) {

        JSONObject obj = new JSONObject();

        obj.put("request_status", "redirect");
        obj.put("response_id", requestId);
        obj.put("next_auth", dynamicAuth);
        obj.put("poll_rate", pollRate);

        return new APIResponse(clientSession, obj, ResponseCode.REDIRECT_CONTINUE);

    }

}
