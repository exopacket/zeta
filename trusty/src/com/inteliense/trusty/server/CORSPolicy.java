package com.inteliense.trusty.server;

import java.util.ArrayList;

public class CORSPolicy {

    private ArrayList<String> origins;
    private ArrayList<String> headers;
    private ArrayList<String> methods;
    private boolean isPermitted = false;

    public CORSPolicy(boolean isPermitted) {
        this.isPermitted = isPermitted;
    }

    public void isPermitted(boolean val) {
        isPermitted = val;
    }

    public boolean isPermitted() {
        return isPermitted;
    }

    public void setOrigins(String[] origins) {
        for(int i=0; i<origins.length; i++) {
            addOrigin(origins[i]);
        }
    }

    public void setHeaders(String[] headers) {
        for(int i=0; i<headers.length; i++) {
            addHeader(headers[i]);
        }
    }

    public void setMethods(String[] methods) {
        for(int i=0; i<methods.length; i++) {
            addMethod(methods[i]);
        }
    }

    public void addOrigin(String origin) {
        origins.add(origin);
    }

    public void addHeader(String header) {
        headers.add(header);
    }

    public void addMethod(String method) {
        methods.add(method);
    }

    public String[] getOrigins() {
        if(origins.size() == 0)
            return new String[]{"*"};
        return toArr(origins);
    }

    public String[] getHeaders() {
        if(headers.size() == 0)
            return new String[]{"Origin", "X-Requested-With",
                    "Content-Type", "Accept",
                    "X-Api-Key", "X-Request-Timestamp", "X-Request-Signature",
                    "X-Api-Session-Id", "X-Api-Key-Set-Id",
                    "X-Api-User-Id", "X-Api-Client-Id", "X-Api-Session-Authorization"
            };
        return toArr(headers);
    }

    public String[] getMethods() {
        if(methods.size() == 0)
            return new String[]{"GET", "POST"};
        return toArr(methods);
    }

    public String getCommaSeparated(String[] arr) {
        String retVal = "";
        for(int i=0; i<arr.length; i++) {
            if(i == 0)
                retVal += arr[i];
            else
                retVal += ", " + arr[i];
        }
        return retVal;
    }

    private String[] toArr(ArrayList<String> list) {
        String[] retVal = new String[list.size()];
        for(int i=0; i<retVal.length; i++) {
            retVal[i] = list.get(i);
        }
        return retVal;
    }

}
