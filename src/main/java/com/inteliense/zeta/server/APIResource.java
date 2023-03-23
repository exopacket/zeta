package com.inteliense.zeta.server;

import java.util.ArrayList;

public abstract class APIResource implements APIExecute {

    private ArrayList<String> parameters = new ArrayList<String>();
    private String requestMethod = "GET";
    private String value = "";
    private boolean isAsync = false;

    public APIResource() {}
    public APIResource(String requestMethod) {
        this.requestMethod = requestMethod;
    }

    public void setParameters(String[] parameters) {
        for(int i=0; i<parameters.length; i++) {
            this.parameters.add(parameters[i]);
        }
    }

    public void setParameters(ArrayList<String> parameters) {
        this.parameters = parameters;
    }

    public void addParameter(String key) {
        if(!inArray(key))
            parameters.add(key);
    }

    public boolean inArray(String key) {
        return parameters.contains(key);
    }
    public ArrayList<String> getParameters() {
        return parameters;
    }

    public String getRequestMethod() {
        return requestMethod;
    }

    public void setRequestMethod(String requestMethod) {
        this.requestMethod = requestMethod.toUpperCase();
    }

    public void setName(String val) {
        value = val;
    }

    public String getName() {
        return value;
    }

    public boolean isAsync() {
        return isAsync;
    }

    public void isAsync(boolean val) {
        isAsync = val;
    }
}
