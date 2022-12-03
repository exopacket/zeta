package com.inteliense.trusty.server;

import com.inteliense.trusty.utils.EncodingUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;

public class Parameters {

    HashMap<String, String> values;

    public Parameters(HashMap<String, String> values) {
        this.values = values;
    }

    public JSONObject getJsonObj(String key) {
        JSONObject obj = new JSONObject(values);
        return obj;
    }

    public JSONArray getJsonArr(String key) {
        JSONObject obj = new JSONObject(values);
        return (JSONArray) obj.get(key);
    }

    public int getInt(String key) {

        return Integer.parseInt(values.get(key));

    }

    public String getString(String key) {
        return values.get(key);
    }

    public double getDouble(String key) {
        return Double.parseDouble(values.get(key));
    }

    public boolean getBoolean(String key) throws Exception {

        String val = values.get(key).toUpperCase();

        if(val.equals("TRUE") || val.equals("1")) {
            return true;
        } else if(val.equals("FALSE") || val.equals("0")) {
            return false;
        }

        throw new Exception();

    }

    public String[] getArr(String key, String delimiter) {
        return EncodingUtils.splitStr(values.get(key), delimiter);
    }

    public LocalDateTime getDateTimeFromTimestamp(String key) {

        return LocalDateTime.ofEpochSecond(
                Long.valueOf(values.get(key)), 0, ZoneOffset.UTC
        );

    }

    public int getInt(JSONObject inputObj, String key) {

        return Integer.parseInt((String) inputObj.get(key));

    }

    public String getString(JSONObject inputObj, String key) {
        return (String) inputObj.get(key);
    }

    public double getDouble(JSONObject inputObj, String key) {
        return Double.parseDouble((String) inputObj.get(key));
    }

    public boolean getBoolean(JSONObject inputObj, String key) throws Exception {

        String val = ((String) inputObj.get(key)).toUpperCase();

        if(val.equals("TRUE") || val.equals("1")) {
            return true;
        } else if(val.equals("FALSE") || val.equals("0")) {
            return false;
        }

        throw new Exception();

    }

    public String[] getArr(String key, String delimiter, JSONObject inputObj) {
        return EncodingUtils.splitStr(((String) inputObj.get(key)), delimiter);
    }

    public LocalDateTime getDateTimeFromTimestamp(JSONObject inputObj, String key) {

        return LocalDateTime.ofEpochSecond(
                Long.valueOf(((String) inputObj.get(key))), 0, ZoneOffset.UTC
        );

    }

}
