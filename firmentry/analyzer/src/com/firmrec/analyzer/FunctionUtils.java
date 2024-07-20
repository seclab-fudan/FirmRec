package com.firmrec.analyzer;

import com.firmrec.utils.StringUtils;
import ghidra.program.model.listing.Function;

public class FunctionUtils {
    public static String getFunctionID(Function function) {
        return function.getName() + "_" + function.getEntryPoint().toString();
    }

    public static String getCallingId(long address, String functionId) {
        return StringUtils.convertHexString(address, 16) + ":" + functionId;
    }

    public static long getCallingAddress(String callingId) {
        String[] tmp = callingId.split(":");
        return Long.parseLong(tmp[0].substring(2), 16);
    }

    public static boolean isJNIName(String functionName) {
        if (!functionName.startsWith("Java_")) {
            return false;
        }
        return true;
    }
}
