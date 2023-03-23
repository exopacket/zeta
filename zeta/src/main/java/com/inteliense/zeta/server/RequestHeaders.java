package com.inteliense.zeta.server;

import com.inteliense.zeta.utils.EncodingUtils;
import com.sun.net.httpserver.Headers;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Map.*;

public class RequestHeaders {

    private HashMap<String, String> values = new HashMap<String, String>();

    public RequestHeaders(Headers headers) {

        Set<Entry<String, List<String>>> all = headers.entrySet();
        Iterator<Entry<String, List<String>>> iterator = all.iterator();

        while(iterator.hasNext()) {
            Entry<String, List<String>> curr = iterator.next();
            String key = curr.getKey();
            String value = "";
            List<String> values = curr.getValue();
            for(int i=0; i<values.size(); i++) {
                if(i==0)
                    value += values.get(i);
                else
                    value += "," + values.get(i);
            }
            this.values.put(key.toUpperCase(), value);
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
