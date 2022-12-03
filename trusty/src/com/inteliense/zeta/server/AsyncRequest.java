package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.EncodingUtils;
import com.inteliense.trusty.utils.SHA;

import java.time.LocalDateTime;

public class AsyncRequest {
    private LocalDateTime lastTimestamp;
    private String staticResponseId;
    private String dynamicRequestAuth;
    private APIResponse response;
    private ClientSession clientSession;
    private boolean requestComplete = false;
    private int perMinute = 60;

    private APIResource asyncResource;

    public AsyncRequest(ClientSession clientSession, LocalDateTime lastTimestamp, String staticResponseId, String initialRequestAuth, int perMinute) {

        this.clientSession = clientSession;
        this.lastTimestamp = lastTimestamp;
        this.staticResponseId = staticResponseId;
        this.dynamicRequestAuth = initialRequestAuth;
        this.perMinute = perMinute;

    }
    public String getDynamicRequestAuth() {
        return dynamicRequestAuth;
    }

    public String getRequestId() {
        return staticResponseId;
    }

    public boolean requestAuthVerifies(String received) {
        String hmac = SHA.getHmac384(getDynamicRequestAuth(),
                EncodingUtils.fromHex(clientSession.getSession().getRandomBytes()));
        boolean res = hmac.equals(received);
        if(res)
            this.dynamicRequestAuth = SHA.get384(hmac);
        return res;
    }

    public LocalDateTime getLastTimestamp() {
        return lastTimestamp;
    }

    public APIResponse getResponse() {
        return response;
    }

    public APIResponse getContinue() {
        return APIResponse.getContinue(clientSession, getRequestId(), getDynamicRequestAuth(), getPollRate());
    }
    public void requestComplete(APIResponse response) {
        this.response = response;
        requestComplete = true;
    }

    public boolean isRequestComplete() {
        return requestComplete;
    }

    public int getPollRate() {
        return Math.round(perMinute / 60) * 1000;
    }

    public boolean newPoll() {

        clientSession.getSession().newRequest();
        clientSession.getClient().newRequest();
        lastTimestamp = LocalDateTime.now();

        return clientSession.getSession().getRecentRequests() >= perMinute;

    }

    public APIResource createResource(APIResponseServer server) {

        APIResource resource = server.addResource(staticResponseId, new String[]{"authorization"}, new APIResource() {
            @Override
            public APIResponse execute(ClientSession clientSession, Parameters params, RequestHeaders headers) throws Exception {

                return server.processRequest(clientSession, this, params, headers);

            }

        });
        asyncResource = resource;
        return resource;

    }

    public void closeRequest(APIResponseServer server) {
        server.removeResource(server.getApiResources().getIndex(staticResponseId));
    }

    public void setAsyncResource(APIResource asyncResource) {
        this.asyncResource = asyncResource;
    }
}