package com.firmrec.rule;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


/**
 * This Checker is used to find all functions match the dependencies
 * 1. Function scopes
 * 2. Function name
 * 3. Function calling
 * 4. Function flows
 * 5. Calling function arguments
 * 6. ...
 */
public class FunctionCheckerRule extends CheckerRule {

    /**
     * Scopes of searching functions
     * */
    public static final int FUNCTION_SCOPE_ALL = 0;
    public static final int FUNCTION_SCOPE_DEPENDENCY = 1;
    public static final int FUNCTION_SCOPE_JNI = 2;

    private int functionScope;
    private FunctionCheckerRule functionScopeDependency;
    /**
     * The name of searching functions
     */
    private String functionName;
    /**
     * The address of searching functions
     */
    private long functionAddress;
    /**
     * The number of searching functions' arguments
     * */
    private int functionArgumentsCount;
    /**
     * The name of searching functions calling
     */
    private ArrayList<String> functionCallings;
    private FunctionCheckerRule functionCallingsDependency;
    /**
     * The function flows of searching functions calling
     */
    private ArrayList<ArrayList<String>> functionFlows;
    /**
     * The arguments of called functions in searching functions
     * */
    private HashMap<String, ArrayList<FunctionArgumentDependency>> functionArguments;
    /**
     * The functions can reach to all searching functions
     * */
    private ArrayList<String> functionBeReachedFrom;
    private FunctionCheckerRule functionBeReachedFromDependency;
    /**
     * The function can be reached from searching function
     * */
    private ArrayList<String> functionCanReachTo;
    private FunctionCheckerRule functionCanReachToDependency;

    public FunctionCheckerRule(String checkerName) {
        super(checkerName);
        this.functionScope = FunctionCheckerRule.FUNCTION_SCOPE_ALL;
        this.functionName  = "";
        this.functionAddress = 0x0;

        this.functionCallings = new ArrayList<>();
        this.functionFlows = new ArrayList<>();
        this.functionArguments = new HashMap<>();
        this.functionBeReachedFrom = new ArrayList<>();
        this.functionCanReachTo = new ArrayList<>();
    }

    // Function scope
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

    // Function name
    public void setFunctionName(String s) {
        this.functionName = s;
    }

    public String getFunctionName() {
        return this.functionName;
    }

    public void setFunctionAddress(long address) {
        this.functionAddress = address;
    }

    public long getFunctionAddress() {
        return this.functionAddress;
    }

    public void setFunctionArgumentsCount(int functionArgumentsCount) {
        this.functionArgumentsCount = functionArgumentsCount;
    }

    public int getFunctionArgumentsCount() {
        return this.functionArgumentsCount;
    }

    // Function callings
    public void addFunctionCallingsTo(List<String> callings) {
        this.functionCallings.addAll(callings);
    }

    public ArrayList<String> getFunctionCallings() {
        return this.functionCallings;
    }

    public void setFunctionCallingsDependency(FunctionCheckerRule functionCallingsDependency) {
        this.functionCallingsDependency = functionCallingsDependency;
    }

    public FunctionCheckerRule getFunctionCallingsDependency() {
        return this.functionCallingsDependency;
    }

    // Function flows
    public void addFunctionFlows(List<String> flow) {
        this.functionFlows.add(new ArrayList<>(flow));
    }

    public ArrayList<ArrayList<String>> getFunctionFlows() {
        return this.functionFlows;
    }

    // Function arguments
    public void addFunctionArgumentType(String s, int argumentIndex, int argumentType) {
        FunctionArgumentDependency dependency = new FunctionArgumentDependency(argumentIndex);
        dependency.setArgumentType(argumentType);
        this.addFunctionArgumentDependency(s, dependency);
    }

    public HashMap<String, ArrayList<FunctionArgumentDependency>> getFunctionArguments() {
        return this.functionArguments;
    }

    public void addFunctionArgumentValue(String s, int argumentIndex, int relation, long value) {
        FunctionArgumentDependency dependency = new FunctionArgumentDependency(argumentIndex);
        dependency.setArgumentValue(relation, value);
        this.addFunctionArgumentDependency(s, dependency);
    }

    private void addFunctionArgumentDependency(String s, FunctionArgumentDependency dependency) {
        if (!this.functionArguments.containsKey(s)) {
            this.functionArguments.put(s, new ArrayList<>());
        }
        this.functionArguments.get(s).add(dependency);
    }

    // Function be reached from
    public void addFunctionBeReachedFrom(List<String> from) {
        this.functionBeReachedFrom.addAll(from);
    }

    public ArrayList<String> getFunctionBeReachedFrom() {
        return this.functionBeReachedFrom;
    }

    public void setFunctionBeReachedFromDependency(FunctionCheckerRule functionBeReachedFromDependency) {
        this.functionBeReachedFromDependency = functionBeReachedFromDependency;
    }

    public FunctionCheckerRule getFunctionBeReachedFromDependency() {
        return this.functionBeReachedFromDependency;
    }

    // Function can reach to
    public void addFunctionCanReachTo(List<String> to) {
        this.functionCanReachTo.addAll(to);
    }

    public ArrayList<String> getFunctionCanReachTo() {
        return this.functionCanReachTo;
    }

    public void setFunctionCanReachToDependency(FunctionCheckerRule functionCanReachToDependency) {
        this.functionCanReachToDependency = functionCanReachToDependency;
    }

    public FunctionCheckerRule getFunctionCanReachToDependency() {
        return this.functionCanReachToDependency;
    }


}
