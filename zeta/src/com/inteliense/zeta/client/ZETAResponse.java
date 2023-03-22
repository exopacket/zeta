package com.inteliense.zeta.client;

import com.inteliense.zeta.types.ZeroTrustResponseType;
import com.inteliense.zeta.utils.AES;
import com.inteliense.zeta.utils.EncodingUtils;
import com.inteliense.zeta.utils.Random;
import com.inteliense.zeta.utils.SHA;
import org.json.simple.JSONObject;

public class ZETAResponse {

    private int status;
    private ResponseHeaders headers;
    private JSONObject data;
    private ZeroTrustResponseType responseType;
    private String nextAuthorization;
    private String nextSecretKey;
    private String nextIv;
    private String currentSecretKey;
    private boolean verified = false;

    public ZETAResponse(int status, ResponseHeaders headers, JSONObject data, String apiKey, String secret, String random, ZeroTrustResponseType responseType) {
        this.status = status;
        this.headers = headers;
        this.data = data;
        this.responseType = responseType;
        this.verified = verify(apiKey, secret, random);
    }

    public int getStatus() { return this.status; }

    public ResponseHeaders getHeaders() { return this.headers; }

    public JSONObject getData() { return this.data; }

    public boolean isVerified() {
        return this.verified;
    }

    public String sessionAuthorization() {
        return headers.getString("X-Api-Session-Authorization");
    }

    public String nextSessionAuthorization() {
        return SHA.getHmac384(sessionAuthorization(), EncodingUtils.fromHex(random()));
    }

    public String authorization() {
        return headers.getString("X-Api-Authorization");
    }

    public String nextAuthorization() {
        return this.nextAuthorization;
    }

    public String nextRandom() {
        return this.nextIv;
    }

    public String nextSecretKey() {
        return this.nextSecretKey;
    }

    public String currentSecretKey() {
        return this.currentSecretKey;
    }
    public String random() {
        return headers.getString("X-Api-Random-Bytes");
    }

    private boolean verify(String apiKey, String secretKey, String random) {

        if(!headers.contains("X-Api-Authorization")) return false;
        if(!headers.contains("X-Api-Random-Bytes")) return false;
        if(headers.getString("X-Api-Random-Bytes").length() != 32) return false;

        String received = headers.getString("X-Api-Authorization");
        String iv = headers.getString("X-Api-Random-Bytes");

        byte[] receivedCipherText = EncodingUtils.fromHex(received);
        byte[] receivedIv = EncodingUtils.fromHex(iv);
        byte[] calculatedHash = EncodingUtils.fromHex(SHA.getHmac512(secretKey, apiKey));
        byte[] actualCipherText = subtractBytes(receivedCipherText, calculatedHash);
        byte[] decryptedSecretKeyBytes = AES.cbc(actualCipherText, EncodingUtils.fromHex(random), receivedIv, false);
        String decryptedSecretKey = new String(decryptedSecretKeyBytes);
        String secretKeyPrefix = (decryptedSecretKey.length() > 1) ? decryptedSecretKey.substring(0, 7) : "";
        if(!secretKeyPrefix.equals("secret_")) return false;
        String nextHash = SHA.getHmac512(decryptedSecretKey, apiKey);
        String serverSecretKey = Random.str(56, "secret");
        byte[] newIv = Random.generateIv(128);
        byte[] nextSecretCipherText = AES.cbc(serverSecretKey.getBytes(), EncodingUtils.fromHex(random), newIv, true);
        byte[] nextHashBytes = EncodingUtils.fromHex(nextHash);
        byte[] signingKey = addBytes(nextSecretCipherText, nextHashBytes);
        this.currentSecretKey = decryptedSecretKey;
        this.nextAuthorization = EncodingUtils.getHex(signingKey);
        this.nextIv = EncodingUtils.getHex(newIv);
        this.nextSecretKey = serverSecretKey;

        return true;

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
