package com.firmrec.model;

import com.firmrec.utils.StringUtils;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;

public class ProgramVariable {

    public final static int VARIABLE_SPACE_UNKNOWN = 0;
    public final static int VARIABLE_SPACE_CONST = 1;
    public final static int VARIABLE_SPACE_REGISTER = 2;
    public final static int VARIABLE_SPACE_STACK = 3;
    public final static int VARIABLE_SPACE_UNIQUE = 4;
    public final static int VARIABLE_SPACE_MEMORY = 5;
    public final static int VARIABLE_SPACE_VARIABLE = 6;

    private Varnode varnode;
    private String variableId;
    private int variableSpace;
    private long variableValue;
    private String reverseName; // For register is its name
    // This field save the called address
    // when the value comes from CALL
    private long callAddress;

    private ArrayList<ProgramVariable> dependencies;
    private int variableFromOp;

    /**
     * Is parameter?
     */
    private boolean isParameter;
    private int parameterIndex;

    private boolean isArgument;
    private int argumentIndex;

    public ProgramVariable(Varnode varnode) {
        this.variableSpace = VARIABLE_SPACE_UNKNOWN;
        this.isParameter = false;
        this.dependencies = new ArrayList<>();
        this.variableId = StringUtils.getRandomUUID();
        this.varnode = varnode;
    }

    public void setCallAddress(long callAddress) {
        this.callAddress = callAddress;
    }

    public long getCallAddress() {
        return this.callAddress;
    }

    public boolean isConstant() {
        return this.variableSpace == VARIABLE_SPACE_CONST;
    }

    public void setConstantValue(long constantValue) {
        this.variableSpace = VARIABLE_SPACE_CONST;
        this.variableValue = constantValue;
    }

    public long getConstantValue() {
        if (this.variableSpace != VARIABLE_SPACE_CONST)
            return 0;
        return this.variableValue;
    }

    public boolean isMemory() {
        return this.variableSpace == VARIABLE_SPACE_MEMORY;
    }

    public void setMemoryValue(long memoryValue) {
        this.variableSpace = VARIABLE_SPACE_MEMORY;
        this.variableValue = memoryValue;
    }

    public long getMemoryValue() {
        if (this.variableSpace != VARIABLE_SPACE_MEMORY)
            return 0;
        return this.variableValue;
    }

    public boolean isRegister() {
        return this.variableSpace == VARIABLE_SPACE_REGISTER;
    }

    public void setRegisterIndex(int registerIndex) {
        this.variableSpace = VARIABLE_SPACE_REGISTER;
        this.variableValue = registerIndex;
    }

    public void setRegisterIndex(String registerName) {
        // sp: -1
        this.variableSpace = VARIABLE_SPACE_REGISTER;
        this.reverseName = registerName;
        try {
            if (registerName.startsWith("r")) {
                this.variableValue = Integer.parseInt(registerName.substring(1));
            } else if (registerName.startsWith("x")) {
                this.variableValue = Integer.parseInt(registerName.substring(1));
            } else if (registerName.startsWith("w")) {
                this.variableValue = Integer.parseInt(registerName.substring(1));
            } else if (registerName.equals("sp")) {
                this.variableValue = -1;
            } else {
                this.variableValue = -2;
                // System.out.println(registerName);
            }
        } catch (Exception ignored) {
            this.variableValue = -2;
        }
    }

    public int getRegisterIndex() {
        if (this.variableSpace != VARIABLE_SPACE_REGISTER)
            return -1;
        return (int) this.variableValue;
    }

    public boolean isStack() {
        return this.variableSpace == VARIABLE_SPACE_STACK;
    }

    public void setStackOffset(int stackOffset) {
        this.variableSpace = VARIABLE_SPACE_STACK;
        this.variableValue = stackOffset;
    }

    public int getStackOffset() {
        if (this.variableSpace != VARIABLE_SPACE_STACK)
            return -1;
        return (int) this.variableValue;
    }

    public boolean isUnique() {
        return this.variableSpace == VARIABLE_SPACE_UNIQUE;
    }

    public void setUniqueValue(long uniqueValue) {
        this.variableSpace = VARIABLE_SPACE_UNIQUE;
        this.variableValue = uniqueValue;
    }

    public int getUniqueValue() {
        if (this.variableSpace != VARIABLE_SPACE_UNIQUE)
            return 0;
        return (int) this.variableValue;
    }

    public boolean isVariable() {
        return this.variableSpace == VARIABLE_SPACE_VARIABLE;
    }

    public void setVariableValue(long variableValue) {
        this.variableSpace = VARIABLE_SPACE_VARIABLE;
        this.variableValue = variableValue;
    }

    public long getVariableValue() {
        if (this.variableSpace != VARIABLE_SPACE_VARIABLE)
            return 0;
        return this.variableValue;
    }

    public boolean isParameter() {
        return this.isParameter;
    }

    public void setParameter(boolean parameter) {
        this.isParameter = parameter;
    }

    public int getParameterIndex() {
        return this.parameterIndex;
    }

    public void setParameterIndex(int parameterIndex) {
        this.parameterIndex = parameterIndex;
    }

    public void addDependency(ProgramVariable dependency) {
        // System.out.println(this.variableId);
        // System.out.println(this.dependencies.size());
        if (this.dependencies.contains(dependency)) {
            return;
        }
        this.dependencies.add(dependency);
    }

    public ArrayList<ProgramVariable> getDependencies() {
        return this.dependencies;
    }

    public boolean containsDependency(Varnode varnode) {
        HashSet<ProgramVariable> visited = new HashSet<>();
        LinkedList<ProgramVariable> workingList = new LinkedList<>();
        ArrayList<ProgramVariable> results = new ArrayList<>();
        workingList.offer(this);

        while (!workingList.isEmpty()) {
            ProgramVariable current = workingList.poll();
            if (visited.contains(current))
                continue;
            visited.add(current);
            if (current.varnode.equals(varnode))
                return true;

            if (current.getDependencies().size() == 0 ||
                    current.getVariableFromOp() == PcodeOp.CALL ||
                    current.getVariableFromOp() == PcodeOp.CALLIND) {
                results.add(current);
            } else {
                for (ProgramVariable tmpVariable : current.getDependencies()) {
                    workingList.offer(tmpVariable);
                }
            }
        }

        return false;
    }

    public boolean containsDependency(ProgramVariable variable) {
        return containsDependency(variable.varnode);
    }

    public int getVariableFromOp() {
        return this.variableFromOp;
    }

    public void setVariableFromOp(int variableFromOp) {
        this.variableFromOp = variableFromOp;
    }

    // @Override
    // public String toString() {
    // String[] spacesString = {"Unknown", "Const", "Register", "Stack", "Unique",
    // "Memory"};
    // StringBuilder description = new StringBuilder();
    // if (this.variableSpace == VARIABLE_SPACE_REGISTER || this.variableSpace ==
    // VARIABLE_SPACE_STACK) {
    // description.append(spacesString[this.variableSpace]).append("
    // (").append(this.variableValue).append(")");
    // } else if (this.variableSpace == VARIABLE_SPACE_MEMORY) {
    // description.append(spacesString[this.variableSpace]).append("
    // (").append(StringUtils.convertHexString(this.variableValue, 16)).append(")");
    // } else {
    // description.append(spacesString[this.variableSpace]).append(":
    // ").append(this.variableValue);
    // }
    //
    // if (this.isParameter()) {
    // description.append(" [").append(this.parameterIndex).append("]");
    // }
    //
    // if (this.dependencies.size() > 0) {
    // description.append(" ").append(this.variableFromOp);
    // if (this.variableFromOp == PcodeOp.CALL) {
    // description.append("
    // (").append(StringUtils.convertHexString(this.callAddress, 16)).append(")");
    // }
    // for (ProgramVariable dependency: this.dependencies) {
    // description.append("\n");
    // String[] lines = dependency.toString().split("\n");
    // for (int i = 0; i < lines.length; ++i) {
    // String line = lines[i];
    // description.append("\t").append(line);
    // if (i != lines.length - 1) description.append("\n");
    // }
    // }
    // }
    //
    // return description.toString();
    //// return this.variableId + " " + this.varnode + "(" +
    // this.dependencies.size() + ")";
    // }

    public boolean isArgument() {
        return this.isArgument;
    }

    public void setArgument(boolean argument) {
        this.isArgument = argument;
    }

    public int getArgumentIndex() {
        return this.argumentIndex;
    }

    public void setArgumentIndex(int argumentIndex) {
        this.argumentIndex = argumentIndex;
    }

    public boolean equals(ProgramVariable programVariable) {
        return this.varnode.equals(programVariable.varnode);
    }

    public int hashCode() {
        return this.varnode.hashCode();
    }
}
