package com.firmrec.model;

import com.firmrec.model.ProgramFunction;
import com.firmrec.utils.StringUtils;

import java.util.ArrayList;

public class ProgramTrace {
    private ArrayList<String> traces;
    private ArrayList<ProgramFunction> functionTraces;

    public ProgramTrace(ArrayList<String> traces, ArrayList<ProgramFunction> functionTraces) {
        this.traces = traces;
        this.functionTraces = functionTraces;
    }

    public ArrayList<String> getTraces() {
        return this.traces;
    }

    public ArrayList<ProgramFunction> getFunctionTraces() {
        return this.functionTraces;
    }

    @Override
    public String toString() {
        StringBuilder description = new StringBuilder();
        ProgramFunction beginFunction = this.getFunctionTraces().get(0);
        description.append(beginFunction.getFunctionName()).append(" (").append(StringUtils.convertHexString(beginFunction.getAddress(), 8)).append(")");
        for (int i = 1; i < this.getFunctionTraces().size(); ++i) {
            ProgramFunction tmpFunction = this.getFunctionTraces().get(i);
            description.append(" -> ").append(tmpFunction.getFunctionName()).append(" (").append(StringUtils.convertHexString(tmpFunction.getAddress(), 8)).append(")");
        }
        return description.toString();
    }

    @Override
    public boolean equals(Object obj) {
        ProgramTrace other = (ProgramTrace) obj;
        if (traces.size() != other.getTraces().size()) {
            return false;
        }
        for (int i = 0; i < this.traces.size(); ++i) {
            if (!this.traces.get(i).equals(other.getTraces().get(i))) {
                return false;
            }
        }
        return true;
    }
}
