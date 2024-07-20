package com.firmrec.analyzer;

import com.firmrec.model.ProgramVariable;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;

public class CallArgument {
    private Address callingAddress;
    private int argumentIndex;
    private Varnode argument;
    private ProgramVariable variable;

    public CallArgument(Address callingAddress, int argumentIndex, Varnode argument) {
        this.callingAddress = callingAddress;
        this.argumentIndex = argumentIndex;
        this.argument = argument;
    }

    public Address getCallingAddress() {
        return callingAddress;
    }

    public int getArgumentIndex() {
        return argumentIndex;
    }

    public void setArgumentIndex(int argumentIndex) {
        this.argumentIndex = argumentIndex;
    }

    public Varnode getArgument() {
        return argument;
    }

    public void setArgument(Varnode argument) {
        this.argument = argument;
    }

    public void setVariable(ProgramVariable variable) {
        this.variable = variable;
        this.variable.setArgument(true);
        this.variable.setArgumentIndex(this.argumentIndex);
    }

    public ProgramVariable getVariable() {
        return this.variable;
    }

    public ArrayList<Long> getPossibleConst(int level) {
        ArrayList<Long> results = new ArrayList<>();
        if (level == 0) {
            if (this.variable.isConstant()) {
                results.add(this.variable.getConstantValue());
            }
        } else {
            // To-Do: ...
        }
        return results;
    }

    public ArrayList<ProgramVariable> getSourceVariables() {
        // System.out.println(this.getVariable());
        HashSet<ProgramVariable> visited = new HashSet<>();
        LinkedList<ProgramVariable> workingList = new LinkedList<>();
        ArrayList<ProgramVariable> results = new ArrayList<>();
        workingList.offer(this.variable);

        while (!workingList.isEmpty()) {
            ProgramVariable current = workingList.poll();
            if (visited.contains(current))
                continue;
            visited.add(current);

            if (current.isArgument() && current != this.getVariable()) {
                results.add(current);
            }
            if (current.getDependencies().size() == 0 ||
                    current.getVariableFromOp() == PcodeOp.CALL ||
                    current.getVariableFromOp() == PcodeOp.CALLIND) {
                results.add(current);
            } else if (current.getVariableFromOp() == PcodeOp.PTRSUB ||
                    current.getVariableFromOp() == PcodeOp.PTRADD) {
                results.add(current);
                // We require following code to analyze some constants
                for (ProgramVariable variable : current.getDependencies()) {
                    workingList.offer(variable);
                }
            } else {
                for (ProgramVariable variable : current.getDependencies()) {
                    workingList.offer(variable);
                }
            }
        }

        return results;
    }

    @Override
    public int hashCode() {
        return this.toString().hashCode();
    }

    @Override
    public String toString() {
        return this.callingAddress + "@" + this.argumentIndex;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof CallArgument) {
            CallArgument other = (CallArgument) obj;
            return this.toString().equals(other.toString());
        }
        return false;
    }
}
