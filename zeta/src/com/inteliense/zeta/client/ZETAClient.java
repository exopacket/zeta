package com.inteliense.zeta.client;

import com.inteliense.zeta.types.ZeroTrustRequestType;
import com.inteliense.zeta.types.ZeroTrustResponseType;
import com.inteliense.zeta.utils.*;
import com.inteliense.zeta.utils.Random;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.json.simple.JSONObject;

import java.util.*;

public class ZETAClient {

    private String sessionStoragePath = "";
    private String endpointUri = "";
    private String apiKey = "";
    private String sessionRandom = "";
    private String sessionId = "";

    private String activeSecret = "";
    private String nextSecret = "";
    private String nextRandom = "";
    private String nextAuthorization = "";
    private String nextSessionAuthorization = "";
    private String sessionInitPath = "";
    private String keyTransferPath = "";
    private String sessionClosePath = "";

    public ZETAClient(String apiKey, String secretKey, String endpointUri, String sessionStoragePath) {
        this.apiKey = apiKey;
        this.activeSecret = secretKey;
        this.endpointUri = endpointUri;
        this.sessionStoragePath = sessionStoragePath;
    }


    public ZETAClient(String apiKey, String endpointUri, String sessionStoragePath) {
        this.apiKey = apiKey;
        //this.activeSecret = secretKey;
        this.endpointUri = endpointUri;
        this.sessionStoragePath = sessionStoragePath;
    }


    public JSONObject request(String path, JSONObject body) {



        return null;
    }

    public boolean beginSession(String sessionInitPath, String keyTransferPath, String sessionClosePath) {

        this.sessionInitPath = sessionInitPath;
        this.keyTransferPath = keyTransferPath;
        this.sessionClosePath = sessionClosePath;

        return init();

    }

    private ZETAResponse post(String path, HashMap<String, String> requestHeaders, ZeroTrustRequestType requestType) {

        try {

            HttpClient httpclient = HttpClients.createDefault();
            HttpPost httppost = new HttpPost(this.endpointUri + path);


            httppost.addHeader("Content-Type", "application/json");

            for(Map.Entry<String, String> entry : requestHeaders.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                httppost.addHeader(key, value);
            }

            HttpResponse response = httpclient.execute(httppost);
            ResponseHeaders headers = new ResponseHeaders(response.getAllHeaders());
            HttpEntity entity = response.getEntity();

            String responseStr = "";

            if (entity != null) {
                try (Scanner scnr = new Scanner(entity.getContent())) {
                    while(scnr.hasNextLine()) {
                        responseStr += (responseStr.equals("") ? "" : "\n") + scnr.nextLine();
                    }
                }
            }

            JSONObject data = JSON.getObject(responseStr);

            System.out.println();
            System.out.println();
            System.out.println(responseStr);

            return new ZETAResponse(response.getStatusLine().getStatusCode(), headers, data, this.apiKey, this.activeSecret, this.sessionRandom, ZeroTrustResponseType.values()[requestType.ordinal()]);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;

    }

    private boolean init() {

        String randomBytesHex = getRandomBytes(48);
        String authorization = initialAuthorization(randomBytesHex);
        HashMap<String, String> headers = new HashMap<String, String>();

        headers.put("X-Api-Key", apiKey);
        headers.put("X-Api-Authorization", authorization);
        headers.put("X-Api-Random-Bytes", randomBytesHex);

        sessionRandom = randomBytesHex.substring(0, 64);

        ZETAResponse response = post(this.sessionInitPath, headers, ZeroTrustRequestType.SESSION_INIT);

        if(!response.getData().containsKey("request_status")) return false;
        if(!((String) response.getData().get("request_status")).equals("success")) return false;
        if(!setInitVars(response)) return false;

        sessionId = (String) response.getData().get("session_id");

        headers.clear();
        headers.put("X-Api-Key", apiKey);
        headers.put("X-Api-Session-Id", sessionId);
        headers.put("X-Api-Session-Authorization", nextSessionAuthorization);
        headers.put("X-Api-Authorization", nextAuthorization);
        headers.put("X-Api-Random-Bytes", nextRandom);

        activeSecret = nextSecret;

        response = post(this.keyTransferPath, headers, ZeroTrustRequestType.KEY_TRANSFER);

        if(!response.getData().containsKey("request_status")) return false;
        if(!((String) response.getData().get("request_status")).equals("success")) return false;

        return true;

    }

    private void close() {}

    private boolean setInitVars(ZETAResponse response) {

        if(!response.isVerified()) return false;

        this.activeSecret = response.currentSecretKey();
        this.nextSecret = response.nextSecretKey();
        this.nextRandom = response.nextRandom();
        this.nextAuthorization = response.nextAuthorization();
        this.nextSessionAuthorization = response.nextSessionAuthorization();

        return true;

    }

    private String getRandomBytes(int len) {
        return EncodingUtils.getHex(Random.secure(len));
    }

    private String initialAuthorization(String randomBytes) {

        String aesKey = randomBytes.substring(0, 64);
        String aesIv = randomBytes.substring(64);
        String encryptedSecretKey = AES.HEX.cbc(this.activeSecret, aesKey, aesIv, true);
        byte[] ciphertext = EncodingUtils.fromHex(encryptedSecretKey);
        byte[] calculatedHash = EncodingUtils.fromHex(SHA.getHmac512(this.activeSecret, this.apiKey));
        byte[] encodedCiphertext = addBytes(ciphertext, calculatedHash);
        return EncodingUtils.getHex(encodedCiphertext);

    }

    private byte[] addBytes(byte[] arr1, byte[] arr2) {

        if(arr1.length == arr2.length) {

            byte[] outArr = new byte[arr1.length];

            for(int i=0; i<outArr.length; i++) {
                outArr[i] = (byte) (arr1[i] + arr2[i]);
            }

            return outArr;

        }

        return null;

    }

    private byte[] subtractBytes(byte[] inputArr, byte[] byArr) {

        if(inputArr.length == byArr.length) {

            byte[] outArr = new byte[inputArr.length];

            for(int i=0; i<outArr.length; i++) {
                outArr[i] = (byte) (inputArr[i] - byArr[i]);
            }

            return outArr;

        }

        return null;

    }

}
