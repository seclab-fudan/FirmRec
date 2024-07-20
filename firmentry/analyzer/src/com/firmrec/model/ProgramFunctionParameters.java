package com.firmrec.model;

import java.io.Serializable;

public class ProgramFunctionParameters implements Serializable {
    private int parametersCount;

    public ProgramFunctionParameters(int argumentsCount) {
        this.parametersCount = argumentsCount;
    }

    public int getParametersCount() {
        return this.parametersCount;
    }

}
