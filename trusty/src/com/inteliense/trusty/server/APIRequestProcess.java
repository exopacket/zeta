package com.inteliense.trusty.server;

import org.json.simple.JSONObject;

import java.util.HashMap;

public interface APIRequestProcess {

    HashMap<String, String> parseRequestBody(RemoteClient client, String resource, String body);

    HashMap<String, String> decryptZeroTrust(JSONObject obj, ZeroTrustRequestType type);

}
