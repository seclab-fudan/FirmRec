package com.firmrec.model;

import com.firmrec.analyzer.ProgramCFG;
import com.firmrec.analyzer.ProgramDDG;
import com.firmrec.model.ProgramFunctionParameters;
import com.firmrec.utils.StringUtils;

import java.util.ArrayList;

public class ProgramFunction {
    private long address;
    private String functionId;
    private String functionName;
    private String functionAlias;
    private String functionSignature;
    private ProgramCFG cfg;
    private ProgramDDG ddg;
    private ArrayList<ArrayList<String>> flows;
    private ProgramFunctionParameters parameters;

    public ProgramFunction(long address, String functionId, String functionName, String functionAlias, ProgramCFG cfg,
            ProgramFunctionParameters parameters) {
        this.address = address;
        this.functionId = functionId;
        this.functionName = functionName;
        this.functionAlias = functionAlias;
        this.cfg = cfg;
        this.flows = this.cfg.getFunctionFlows();
        this.parameters = parameters;
    }

    public String getFunctionName() {
        return this.functionName;
    }

    public String getFunctionId() {
        return this.functionId;
    }

    public ArrayList<ArrayList<String>> getFlows() {
        return this.flows;
    }

    public String getFunctionAlias() {
        return this.functionAlias;
    }

    public void setFunctionAlias(String functionAlias) {
        this.functionAlias = functionAlias;
    }

    public String getFunctionSignature() {
        return this.functionSignature;
    }

    public void setFunctionSignature(String functionSignature) {
        this.functionSignature = functionSignature;
    }

    public long getAddress() {
        return address;
    }

    public void setAddress(long address) {
        this.address = address;
    }

    public int getParametersCount() {
        return this.parameters.getParametersCount();
    }

    public void setDdg(ProgramDDG ddg) {
        this.ddg = ddg;
    }

    public ProgramDDG getDdg() {
        return this.ddg;
    }

    public ProgramCFG getCfg() {
        return this.cfg;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ProgramFunction) {
            ProgramFunction function = (ProgramFunction) obj;
            return this.functionId.equals(function.getFunctionId());
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.functionId.hashCode();
    }

    @Override
    public String toString() {
        StringBuilder description = new StringBuilder();
        description.append(StringUtils.convertHexString(this.address, 8)).append(":\t").append(this.functionName);
        description.append(" (").append(this.functionAlias).append(")");
        if (this.functionSignature != null && this.functionSignature.length() > 0) {
            description.append(" [").append(this.functionSignature).append("]");
        }
        return description.toString();
    }
}
