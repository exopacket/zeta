package com.inteliense.trusty.server;

import java.util.HashMap;

public class Parameters {

    HashMap<String, String> values;

    public Parameters(HashMap<String, String> values) {
        this.values = values;
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


}
