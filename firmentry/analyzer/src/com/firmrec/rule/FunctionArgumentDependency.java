package com.firmrec.rule;

public class FunctionArgumentDependency {
    public static final int ARGUMENT_TYPE_ANY = 0;
    public static final int ARGUMENT_TYPE_CONST = 1;
    public static final int ARGUMENT_TYPE_VARIABLE = 2;
    public static final int ARGUMENT_TYPE_INT_LEFT = 3;
    public static final int ARGUMENT_TYPE_INT_MULT = 4;

    public static final int ARGUMENT_RELATION_EMPTY = 0;
    public static final int ARGUMENT_RELATION_EQ    = 1;
    public static final int ARGUMENT_RELATION_GT    = 2;
    public static final int ARGUMENT_RELATION_GE    = 3;
    public static final int ARGUMENT_RELATION_LT    = 4;
    public static final int ARGUMENT_RELATION_LE    = 5;
    public static final int ARGUMENT_RELATION_NE    = 6;

    private int argumentIndex;

    // Constraints
    private int argumentType;
    private int argumentRelation;
    private long argumentValue;

    public FunctionArgumentDependency(int argumentIndex) {
        this.argumentIndex = argumentIndex;
        this.argumentType = ARGUMENT_TYPE_ANY;
        this.argumentRelation = ARGUMENT_RELATION_EMPTY;
    }

    public void setArgumentType(int argumentType) {
        this.argumentType = argumentType;
    }

    public void setArgumentValue(int argumentRelation, long argumentValue) {
        this.argumentRelation = argumentRelation;
        this.argumentValue = argumentValue;
    }

    public int getArgumentType() {
        return this.argumentType;
    }

    public int getArgumentIndex() {
        return this.argumentIndex;
    }

    public int getArgumentRelation() {
        return this.argumentRelation;
    }

    public long getArgumentValue() {
        return this.argumentValue;
    }
}
