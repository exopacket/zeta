package com.inteliense.trusty.utils;

public class CURL {

    public static String getUrl(String url) throws Exception {

        String[] arr = Exec.withOut("curl " + url);
        String retVal = "";

        for(int i=0; i<arr.length; i++) {
            if(i > 0) retVal += "\n";
            retVal += arr[i];
        }

        return retVal;

    }

}
