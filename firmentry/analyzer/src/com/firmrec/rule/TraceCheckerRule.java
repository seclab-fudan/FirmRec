package com.firmrec.rule;

import java.util.ArrayList;
import java.util.List;

public class TraceCheckerRule extends CheckerRule {

    private ArrayList<String> beginFunctions;
    private FunctionCheckerRule beginFunctionsDependency;

    private ArrayList<String> endFunctions;
    private FunctionCheckerRule endFunctionsDependency;

    public TraceCheckerRule(String checkerName) {
        super(checkerName);
        this.beginFunctions = new ArrayList<>();
        this.endFunctions = new ArrayList<>();
    }

    public void addBeginFunction(List<String> functions) {
        this.beginFunctions.addAll(functions);
    }

    public ArrayList<String> getBeginFunctions() {
        return this.beginFunctions;
    }

    public void setBeginFunctionsDependency(FunctionCheckerRule beginFunctionsDependency) {
        this.beginFunctionsDependency = beginFunctionsDependency;
    }

    public FunctionCheckerRule getBeginFunctionsDependency() {
        return this.beginFunctionsDependency;
    }

    public void addEndFunctions(List<String> functions) {
        this.endFunctions.addAll(functions);
    }

    public ArrayList<String> getEndFunctions() {
        return this.endFunctions;
    }

    public void setEndFunctionsDependency(FunctionCheckerRule endFunctionsDependency) {
        this.endFunctionsDependency = endFunctionsDependency;
    }

    public FunctionCheckerRule getEndFunctionsDependency() {
        return this.endFunctionsDependency;
    }
}
