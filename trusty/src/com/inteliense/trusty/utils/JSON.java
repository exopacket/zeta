package com.inteliense.trusty.utils;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.IOException;
import java.io.StringWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JSON {

    public static JSONObject getObject(String body) {

        try {

            JSONParser parser = new JSONParser();
            Object obj = parser.parse(body);
            JSONObject jsonObj = (JSONObject) obj;

            return jsonObj;

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return new JSONObject();

    }

    public static JSONArray getArray(String body) {

        try {

            JSONParser parser = new JSONParser();
            Object obj = parser.parse(body);
            JSONObject jsonObj = (JSONObject) obj;

            return (JSONArray) jsonObj.get("arr");

        } catch (Exception ex) {

            ex.printStackTrace();

        }

        return new JSONArray();

    }

    public static String getString(JSONObject obj) {

        try {

            StringWriter out = new StringWriter();
            obj.writeJSONString(out);
            return out.toString();

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return "{}";

    }

    public static String verify(String json) {

        final String JSON_REGEX = "((true|false)|[0-9]+|[:,\\{\\}\\[\\]]|((\\\"?).*?([^\\\\]\\\"))|(([^\\\\]\\\").*?(\\\"?))|(('?).*?('))|((').*?('?))|[-\\w.])";
        final String NUMBER_REGEX = "[0-9]+";
        final String STRING_REGEX = "([^\"](\\\\\")?(\\\\)?)+";

        if(json.replaceAll("\\s+", "").equals(""))
            return "false";

        if(json.charAt(0) != '{' || json.charAt(json.length() - 1) != '}') {
            return "false";
        }

        Pattern p = Pattern.compile(JSON_REGEX);
        Pattern pNum = Pattern.compile(NUMBER_REGEX);
        Pattern pStr = Pattern.compile(STRING_REGEX);
        Matcher m = p.matcher(json);

        String minified = "";

        int count = 0;
        int balBrackets = 0;
        int balSquare = 0;
        int end = -1;
        boolean comma = false;

        while(m.find()) {

            String match = json.substring(m.start(), m.end());
            Matcher mNum = pNum.matcher(match);
            Matcher mStr = pStr.matcher(match);

            count++;

            boolean bracket = false;

            if(match.equals("{")) {
                balBrackets++;
                bracket = true;
            }

            if(match.equals("}")) {
                balBrackets--;
                bracket = true;
                if(balBrackets == 0) {
                    minified += match;
                    end = m.end();
                    break;
                }
            }

            if(match.equals("[")) {
                balSquare++;
                bracket = true;
            }

            if(match.equals("]")) {
                balSquare--;
                bracket = true;
            }

            if(match.equals(",") && comma) {
                break;
            } else if(match.equals(",") && !comma) {
                comma = true;
            } else if(!match.equals(",") && comma) {
                comma = false;
            }

            int numValVerified = 0;
            int strVerified = 0;

            boolean strFound = false;

            if(mStr.find() && !bracket && !comma && !match.equals(":")) {

                strFound = true;

                if(mNum.find()) {
                    String tmp = match.substring(mNum.start(), mNum.end());

                    if(tmp.length() == match.length()) {
                        numValVerified = 1;
                    } else {
                        numValVerified = -1;
                    }
                }

                if(numValVerified <= 0) {
                    String tmp = match.substring(mStr.start(), mStr.end());
                    if(tmp.length() == match.length() - 2) {
                        if(match.charAt(0) == '\"' && match.charAt(match.length() - 1) == '\"') {
                            strVerified = 1;
                        } else {
                            strVerified = -1;
                        }
                    } else {
                        strVerified = -1;
                    }
                }

                if(strVerified <= 0 && numValVerified <= 0) {
                    break;
                }

            }

            if(!(strFound || comma || bracket || match.equals(":"))) {
                break;
            }

            end = m.end();
            minified += match;

        }

        if(balBrackets != 0 || balSquare != 0) {
            return "false";
        }

        if(count <= 2) {
            return "false";
        }

        if(end != json.length()) {
            return "false";
        }

        return minified;

    }

}
