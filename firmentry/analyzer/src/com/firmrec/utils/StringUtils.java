package com.firmrec.utils;

import java.util.ArrayList;
import java.util.UUID;

public class StringUtils {

    public static boolean isASCIIString(String s) {
        boolean isASCII = true;
        for (int i = 0; i < s.length(); ++i) {
            int c = s.charAt(i);
            if (c > 0x7F) {
                isASCII = false;
                break;
            }
        }
        return isASCII;
    }


    public static boolean isValidMethodName(String s) {
        int firstC = s.charAt(0);
        if (!((firstC >= 65 && firstC <= 90) ||
                (firstC >= 97 && firstC <= 122) ||
                firstC == 95)) {
            return false;
        }

        for (int i = 0; i < s.length(); ++i) {
            int c = s.charAt(i);
            if (!((c >= 65 && c <= 90) ||
                    (c >= 97 && c <= 122) ||
                    c == 95 ||
                    (c >= 48 && c <= 57))) {
                return false;
            }
        }
        return true;
    }


    public static boolean isValidMethodSignature(String s) {
        String[] identifies = {"V", "Z", "B", "C", "S", "I", "J", "F", "D", "[", "L"};

        if (!s.startsWith("(")) return false;

        if (s.startsWith("()")) {
            String returnIdentify = s.substring(2, 3);
            for (String tmp: identifies) {
                if (tmp.equals(returnIdentify)) {
                    return true;
                }
            }
            return false;
        }

        boolean argMatch = false;
        String argIdentify = s.substring(1, 2);
        for (String tmp: identifies) {
            if (tmp.equals(argIdentify)) {
                argMatch = true;
                break;
            }
        }
        if (!argMatch) {
            return false;
        }

        String returnIdentify = "";
        for (int i = 0; i < s.length(); ++i) {
            char c = s.charAt(i);
            if (c == ')') {
                returnIdentify = s.substring(i + 1, i + 2);
                break;
            }
        }
        boolean returnMatch = false;
        for (String tmp: identifies) {
            if (tmp.equals(returnIdentify)) {
                returnMatch = true;
                break;
            }
        }

        return returnMatch;
    }

    public static String convertHexString(long value, int length) {
        StringBuilder result = new StringBuilder(Long.toString(value, 16));
        int resultLength = result.length();
        if (resultLength < length) {
            for (int i = 0; i < length - resultLength; ++i) {
                result.insert(0, "0");
            }
        }
        return "0x" + result;
    }

    public static String getRandomUUID() {
        return UUID.randomUUID().toString();
    }
}
