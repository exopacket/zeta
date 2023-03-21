package com.inteliense.zeta.client;

import com.inteliense.zeta.utils.AES;
import com.inteliense.zeta.utils.EncodingUtils;
import com.inteliense.zeta.utils.Random;
import com.inteliense.zeta.utils.SHA;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONObject;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class ZETAClient {

    private String sessionStoragePath;
    private String apiKey = "apikey_JnM8qqLoh2CjEM773mMmEUQS3in5cq9VHRiw5iNnXcNeEbuPhqpDZG0OJR9hbtb1Hi8QBkaE";
    private String secretKey = "secret_cYM64CuorsmEkjXGNvmmdhtoSWMlrGq7zCD8Eo0O0jeKrfJ02GsAIwXr";

    public ZETAClient(String sessionStoragePath) {
        this.sessionStoragePath = sessionStoragePath;
    }

    public JSONObject request(JSONObject body) { post(); return null; }

    private void post() {

        try {

            HttpClient httpclient = HttpClients.createDefault();
            HttpPost httppost = new HttpPost("http://127.0.0.1:8181/api/session/init");

            List<NameValuePair> params = new ArrayList<NameValuePair>(2);
            params.add(new BasicNameValuePair("param-1", "12345"));
            params.add(new BasicNameValuePair("param-2", "Hello!"));
            httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));

            String randomBytesHex = getRandomBytes(48);
            String authorization = initialAuthorization(randomBytesHex);
            httppost.addHeader("X-Api-Key", "apikey_JnM8qqLoh2CjEM773mMmEUQS3in5cq9VHRiw5iNnXcNeEbuPhqpDZG0OJR9hbtb1Hi8QBkaE");
            httppost.addHeader("X-Api-Authorization", authorization);
            httppost.addHeader("X-Api-Random-Bytes", randomBytesHex);

            HttpResponse response = httpclient.execute(httppost);
            HttpEntity entity = response.getEntity();

            System.out.println();
            System.out.println();

            if (entity != null) {
                try (Scanner instream = new Scanner(entity.getContent())) {
                    while(instream.hasNextLine()) {
                        System.out.println(instream.nextLine());
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void init() {}

    private void keyTransfer() {}

    private void close() {}

    private String getRandomBytes(int len) {
        return EncodingUtils.getHex(Random.secure(len));
    }

    private String initialAuthorization(String randomBytes) {

        String aesKey = randomBytes.substring(0, 64);
        String aesIv = randomBytes.substring(64);
        String encryptedSecretKey = AES.HEX.cbc(this.secretKey, aesKey, aesIv, true);
        byte[] ciphertext = EncodingUtils.fromHex(encryptedSecretKey);
        byte[] calculatedHash = EncodingUtils.fromHex(SHA.getHmac512(this.secretKey, this.apiKey));
        byte[] encodedCiphertext = addBytes(ciphertext, calculatedHash);
        return EncodingUtils.getHex(encodedCiphertext);

    }

    private String getAuthorization(String secretKey) {
        return "";
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
