package com.firmrec.model;

import com.firmrec.utils.StringUtils;

public class ProgramCallSite {
    private String fromFunction;
    private String fromFunctionId;
    private String toFunction;
    private String toFunctionId;
    private long address;

    public ProgramCallSite(String fromFunction, String fromFunctionId, String toFunction, String toFunctionId, long address) {
        this.fromFunction = fromFunction;
        this.fromFunctionId = fromFunctionId;
        this.toFunction = toFunction;
        this.toFunctionId = toFunctionId;
        this.address = address;
    }

    public String getFromFunctionId() {
        return this.fromFunctionId;
    }

    public String getToFunctionId() {
        return this.toFunctionId;
    }

    public String getFromFunctionName() {
        return this.fromFunction;
    }

    public String getToFunctionName() {
        return this.toFunction;
    }

    public long getAddress() {
        return address;
    }

    @Override
    public String toString() {
        StringBuilder description = new StringBuilder();
        description.append(StringUtils.convertHexString(this.address, 8)).append(":\t");
        description.append(this.fromFunction).append(" ---> ").append(this.toFunction);
        return description.toString();
    }
}
