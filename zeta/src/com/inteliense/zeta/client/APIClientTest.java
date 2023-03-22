package com.inteliense.zeta.client;

public class APIClientTest {

    public static void main(String[] args) throws Exception {

        ZETAClient client = new ZETAClient("apikey_JnM8qqLoh2CjEM773mMmEUQS3in5cq9VHRiw5iNnXcNeEbuPhqpDZG0OJR9hbtb1Hi8QBkaE", "secret_cYM64CuorsmEkjXGNvmmdhtoSWMlrGq7zCD8Eo0O0jeKrfJ02GsAIwXr", "http://127.0.0.1:8181/api", "/home/ryan/.zeta");
        client.beginSession("/session/init", "/session/keys", "/session/close");

    }

}