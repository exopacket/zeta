package com.inteliense.trusty.server;

import java.util.ArrayList;
import java.util.HashMap;

public abstract class APIResource implements APIExec {

    private ArrayList<String> parameters = new ArrayList<String>();
    private HashMap<String, String> values = new HashMap<String, String>();
    private String requestMethod = "GET";
    private boolean requestIsJson = false;


    public void setParameters(String[] parameters) {
        for(int i=0; i<parameters.length; i++) {
            this.parameters.add(parameters[i]);
        }
    }

    public void setParameters(ArrayList<String> parameters) {
        this.parameters = parameters;
    }

    public void addParameter(String key) {
        parameters.add(key);
    }

    public boolean inArray(String key) {
        return parameters.contains(key);
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

    public ArrayList<String> getParameters() {
        return parameters;
    }

    public boolean requestIsJson() {
        return requestIsJson;
    }

    public void setRequestIsJson(boolean requestIsJson) {
        this.requestIsJson = requestIsJson;
    }

    public String getRequestMethod() {
        return requestMethod;
    }

    public void setRequestMethod(String requestMethod) {
        this.requestMethod = requestMethod.toUpperCase();
    }
}
