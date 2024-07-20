package com.firmrec.rule;

import java.util.ArrayList;
import java.util.List;

public class CallSiteCheckerRule extends CheckerRule {

    /**
     * Scopes of searching functions
     * */
    public static final int FUNCTION_SCOPE_ALL = 0;
    public static final int FUNCTION_SCOPE_DEPENDENCY = 1;
    public static final int FUNCTION_SCOPE_JNI = 2;

    private int functionScope;
    private FunctionCheckerRule functionScopeDependency;

    /**
     * The name of searching functions calling
     * */
    private ArrayList<String> functionCallings;
    private FunctionCheckerRule functionCallingsDependency;

    public CallSiteCheckerRule(String checkerName) {
        super(checkerName);
        this.functionScope = FunctionCheckerRule.FUNCTION_SCOPE_ALL;

        this.functionCallings = new ArrayList<>();
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
}
