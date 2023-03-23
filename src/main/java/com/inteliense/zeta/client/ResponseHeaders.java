package com.inteliense.zeta.client;

import com.inteliense.zeta.utils.EncodingUtils;
import org.apache.http.Header;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;

public class ResponseHeaders {

    private HashMap<String, String> values = new HashMap<String, String>();

    public ResponseHeaders(Header[] headers) {

        for(Header header: headers) {
            this.values.put(header.getName().toUpperCase(), header.getValue());
        }

    }

    public boolean contains(String key) {
        return values.containsKey(key.toUpperCase());
    }

    public int getInt(String key) {
        return Integer.parseInt(values.get(key.toUpperCase()));
    }

    public String getString(String key) {
        return (values.get(key.toUpperCase()).contains(",")) ?
                values.get(key.toUpperCase()).replace(",", ", ")
                : values.get(key.toUpperCase());
    }

    public double getDouble(String key) {
        return Double.parseDouble(values.get(key.toUpperCase()));
    }

    public boolean getBoolean(String key) throws Exception {

        String val = values.get(key.toUpperCase()).toUpperCase();

        if(val.equals("TRUE") || val.equals("1")) {
            return true;
        } else if(val.equals("FALSE") || val.equals("0")) {
            return false;
        }

        throw new Exception();

    }

    public String[] getArr(String key) {
        return getArr(key, ",");
    }

    public String[] getArr(String key, String delimiter) {
        return EncodingUtils.splitStr(values.get(key.toUpperCase()), delimiter);
    }

    public LocalDateTime getDateTimeFromTimestamp(String key) {

        return LocalDateTime.ofEpochSecond(
                Long.valueOf(values.get(key.toUpperCase())), 0, ZoneOffset.UTC
        );

    }

}
