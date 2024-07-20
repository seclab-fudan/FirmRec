package com.firmrec.rule;

import java.util.ArrayList;
import java.util.HashMap;

public class SourceSinkCheckerRule extends CheckerRule {

    private ArrayList<String> sourceFunctions;
    private ArrayList<String> sourceArguments;

    private ArrayList<String> sinkFunctions;
    private ArrayList<String> sinkArguments;

    private int functionScope;
    private FunctionCheckerRule functionScopeDependency;
    private HashMap<String, String> functionScopeArguments;
    private boolean entrySources;
    private boolean callingSources;

    public SourceSinkCheckerRule(String checkerName) {
        super(checkerName);
        this.functionScope = FunctionCheckerRule.FUNCTION_SCOPE_ALL;
        this.functionScopeArguments = new HashMap<>();

        this.sourceFunctions = new ArrayList<>();
        this.sourceArguments = new ArrayList<>();

        this.sinkFunctions = new ArrayList<>();
        this.sinkArguments = new ArrayList<>();

        this.entrySources = false;
        this.callingSources = false;
    }

    public void setFunctionScope(int functionScope) {
        this.functionScope = functionScope;
    }

    public int getFunctionScope() {
        return this.functionScope;
    }

    public void setFunctionScopeDependency(FunctionCheckerRule functionScopeDependency) {
        this.functionScope = FunctionCheckerRule.FUNCTION_SCOPE_DEPENDENCY;
        this.functionScopeDependency = functionScopeDependency;
    }

    public FunctionCheckerRule getFunctionScopeDependency() {
        return this.functionScopeDependency;
    }

    public void setFunctionScopeArguments(HashMap<String, String> functionScopeArguments) {
        this.functionScopeArguments = functionScopeArguments;
    }

    public HashMap<String, String> getFunctionScopeArguments() {
        return this.functionScopeArguments;
    }

    public void addSourceFunction(String functionName, String argumentIndex) {
        this.sourceFunctions.add(functionName);
        this.sourceArguments.add(argumentIndex);
    }

    public void addSinkFunction(String functionName, String argumentIndex) {
        this.sinkFunctions.add(functionName);
        this.sinkArguments.add(argumentIndex);
    }

    public void setEntrySources(boolean entrySources) {
        this.entrySources = entrySources;
    }

    public boolean isEntrySources() {
        return this.entrySources;
    }

    public void setCallingSources(boolean callingSources) {
        this.callingSources = callingSources;
    }

    public boolean isCallingSources() {
        return this.callingSources;
    }

    public ArrayList<String> getSourceFunctions() {
        return this.sourceFunctions;
    }

    public ArrayList<String> getSourceArguments() {
        return this.sourceArguments;
    }

    public ArrayList<String> getSinkFunctions() {
        return this.sinkFunctions;
    }

    public ArrayList<String> getSinkArguments() {
        return this.sinkArguments;
    }
}
