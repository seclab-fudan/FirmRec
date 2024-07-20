package com.firmrec.analyzer;

import com.firmrec.model.ProgramConstant;
import com.firmrec.model.ProgramVariable;
import generic.stl.Pair;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.SymbolicPropogator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;

public class ProgramFunctionContext {
    private String functionId;
    private HashMap<Varnode, ProgramVariable> variableContext;
    private HashMap<ProgramVariable, HashSet<Pair<String, Integer>>> variableFromCalling; // PHI like instructions may
                                                                                          // lead to multiple sources
    private HashMap<CallArgument, Pair<String, Integer>> functionArguments;
    private HashMap<CallArgument, ProgramConstant> functionArgumentConstants;
    private HashSet<Pair<String, Long>> refStrings;
    private SymbolicPropogator constSymEval;

    public ProgramFunctionContext(String functionId) {
        this.functionId = functionId;
        this.variableContext = new HashMap<>();
        this.variableFromCalling = new HashMap<>();
        this.functionArguments = new HashMap<>();
        this.functionArgumentConstants = new HashMap<>();
        this.refStrings = new HashSet<>();
        this.constSymEval = null;
    }

    public String getFunctionId() {
        return functionId;
    }

    public ArrayList<ProgramVariable> getSourceVariables(ProgramVariable variable) {
        HashSet<ProgramVariable> visited = new HashSet<>();
        LinkedList<ProgramVariable> workingList = new LinkedList<>();
        ArrayList<ProgramVariable> results = new ArrayList<>();
        workingList.offer(variable);

        while (!workingList.isEmpty()) {
            ProgramVariable current = workingList.poll();
            if (visited.contains(current))
                continue;
            visited.add(current);

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

        return results;
    }

    public void addVariable(Varnode varnode, ProgramVariable variable) {
        if (this.variableContext.containsKey(varnode))
            return;

        // System.out.println();
        this.variableContext.put(varnode, variable);
    }

    public ProgramVariable getVariable(Varnode varnode) {
        return this.variableContext.get(varnode);
    }

    public void addVariableFromCalling(ProgramVariable variable, String callingId) {
        // For compatibility with old code
        this.addVariableFromCalling(variable, callingId, -1);
    }

    public void addVariableFromCalling(ProgramVariable variable, String callingId, int argumentIndex) {
        if (!this.variableFromCalling.containsKey(variable)) {
            this.variableFromCalling.put(variable, new HashSet<>());
        }
        this.variableFromCalling.get(variable).add(new Pair<>(callingId, argumentIndex));
    }

    public void addFunctionArguments(String callingId, int argumentIndex, CallArgument argument) {
        if (!this.functionArguments.containsKey(argument)) {
            this.functionArguments.put(argument, new Pair<>(callingId, argumentIndex));
            this.addVariableFromCalling(argument.getVariable(), callingId, argumentIndex);
        }
    }

    public void addFunctionArgumentConstants(CallArgument argument, ProgramConstant constant) {
        this.functionArgumentConstants.put(argument, constant);
    }

    public ProgramConstant getFunctionArgumentConstant(CallArgument argument) {
        return this.functionArgumentConstants.get(argument);
    }

    public HashSet<String> getCallingIdsFromOutput(ProgramVariable variable) {
        HashSet<String> callingIds = new HashSet<>();
        if (this.variableFromCalling.containsKey(variable)) {
            HashSet<Pair<String, Integer>> items = this.variableFromCalling.get(variable);
            for (Pair<String, Integer> item : items) {
                if (item.second == -1)
                    callingIds.add(item.first);
            }
        }
        return callingIds;
    }

    public HashSet<Pair<String, Integer>> getCallingItemsFromInput(ProgramVariable variable) {
        HashSet<Pair<String, Integer>> callingItems = new HashSet<>();
        if (this.variableFromCalling.containsKey(variable)) {
            HashSet<Pair<String, Integer>> items = this.variableFromCalling.get(variable);
            for (Pair<String, Integer> item : items) {
                if (item.second >= 0)
                    callingItems.add(item);
            }
        }
        return callingItems;
    }

    public HashMap<CallArgument, Pair<String, Integer>> getFunctionArguments() {
        return this.functionArguments;
    }

    public HashMap<CallArgument, ProgramConstant> getFunctionArgumentConstants() {
        return this.functionArgumentConstants;
    }

    public void setConstSymEval(SymbolicPropogator symEval) {
        this.constSymEval = symEval;
    }

    public SymbolicPropogator getConstSymEval() {
        return this.constSymEval;
    }

    public HashSet<Pair<String, Long>> getRefStrings() {
        return refStrings;
    }
}
