package com.firmrec.analyzer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.util.HashMap;

public class CallGraphNode {
    private Function fromFunction;
    private Function toFunction;
    private Address callerAddress;
    private Address calleeAddress;
    private HashMap<Integer, CallArgument> arguments;

    public CallGraphNode(Function fromFunction, Address callerAddress, Function toFunction, Address calleeAddress) {
        this.fromFunction = fromFunction;
        this.callerAddress = callerAddress;

        this.toFunction = toFunction;
        this.calleeAddress = calleeAddress;

        this.arguments = new HashMap<>();
    }

    public Function getFromFunction() {
        return fromFunction;
    }

    public Function getToFunction() {
        return toFunction;
    }

    public Address getCallerAddress() {
        return callerAddress;
    }

    public Address getCalleeAddress() {
        return calleeAddress;
    }

    public void addArgument(int index, CallArgument argument) {
//        CallArgument arg = new CallArgument(index, argument);
        this.arguments.put(index, argument);
    }

    public void clearArgument() {
        this.arguments.clear();
    }

    public CallArgument getArgument(int argumentIndex) {
        return this.arguments.get(argumentIndex);
    }

    public int getArgumentsCount() {
        return this.arguments.size();
    }

    @Override
    public boolean equals(Object obj) {
        CallGraphNode other = (CallGraphNode) obj;
        if (this.getFromFunction() != other.getFromFunction()) return false;
        if (this.getCallerAddress() != other.getCallerAddress()) return false;
        if (this.getToFunction() != other.getToFunction()) return false;
        return this.getCalleeAddress() == other.getCalleeAddress();
    }
}
