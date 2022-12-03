package com.inteliense.trusty.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

public class EncodingUtils {

    public static String getHex(byte[] data) {

        final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

        byte[] hexChars = new byte[data.length * 2];
        for(int j=0; j<data.length; j++) {

            int v = data[j] & 0xFF;
            hexChars[j*2] = HEX_ARRAY[v >>> 4];
            hexChars[j*2+1] = HEX_ARRAY[v & 0x0F];

        }

        return new String(hexChars, StandardCharsets.UTF_8).toLowerCase();

    }

    public static byte[] fromHex(String hex) {

        byte[] val = new byte[hex.length() / 2];

        for(int i=0; i<val.length; i++) {

            int index = i * 2;
            int j = Integer.parseInt(hex.substring(index, index + 2), 16);
            val[i] = (byte) j;

        }

        return val;

    }

    public static String getBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String str) {
        return Base64.getDecoder().decode(str);
    }

    public static String base64ToHex(String base64) {
        byte[] bites = fromBase64(base64);
        return getHex(bites);
    }

    public static String hexToBase64(String hex) {
        byte[] bites = fromHex(hex);
        return getBase64(bites);
    }

    public static String[] splitStr(String input, char delimiter) {
        return splitStr(input, "" + delimiter);
    }

    public static String[] splitStr(String input, String delimiter) {
        //automatic regex search / conversion
        if(delimiter.equals("")) return null;
        String reserved = ".;$;|;(;);[;{;^;?;*;+;\\";
        String[] reservedArr = reserved.split(";");
        int c = 0;for(int i=0; i<reservedArr.length; i++) {
            char rCh = reservedArr[i].charAt(0);
            for(int x=0; x<delimiter.length(); x++) {
                char ch = delimiter.charAt(x);
                if(ch == rCh) c++;
                if(c > 1) break;
            }
            if(c > 1) break;
        }
        if(c > 1 || (delimiter.length() > 1 && c == 1)) {
            return splitStr(input, Pattern.compile(delimiter));
        }
        if(delimiter.length() == 1 && c == 1) {
            String _intellijFix = "$";
            _intellijFix = delimiter;
            String pattern = "\\" + _intellijFix;
            return input.split(pattern);
        } else {
            return input.split(delimiter);
        }
    }

    public static String[] splitStr(String input, Pattern regex) {
        return regex.split(input);
    }

}
