package com.firmrec.analyzer;

import com.firmrec.model.ProgramFunction;
import com.firmrec.model.ProgramTrace;
import com.firmrec.utils.IOUtils;
import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.correlate.Hash;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;

public class ProgramCallGraph {

    private Program program;
    private ProgramAnalyzer programAnalyzer;
    private HashMap<String, Function> functionIds;
    private HashMap<String, ProgramFunction> allFunctions;
    private HashMap<String, ArrayList<CallGraphNode>> functionCalls;
    private HashMap<String, ArrayList<ArrayList<Long>>> functionCallAddresses;
    private HashMap<String, Boolean> argumentsAnalyzed;
    private HashMap<String, ArrayList<ProgramTrace>> callTraces;

    public ProgramCallGraph(Program program, ProgramAnalyzer analyzer, HashMap<String, Function> functions,
            HashMap<String, ProgramFunction> allFunctions, String projectDirectory) {
        this.program = program;
        this.programAnalyzer = analyzer;

        this.functionIds = new HashMap<>();
        this.functionIds.putAll(functions);

        this.allFunctions = new HashMap<>();
        this.allFunctions.putAll(allFunctions);

        this.functionCalls = new HashMap<>();
        this.callTraces = new HashMap<>();
        this.argumentsAnalyzed = new HashMap<>();

        FunctionManager functionManager = this.program.getFunctionManager();
        ReferenceManager referenceManager = this.program.getReferenceManager();

        // Get call nodes and call traces for each function
        this.functionCallAddresses = (HashMap<String, ArrayList<ArrayList<Long>>>) IOUtils.loadCache(projectDirectory,
                "call");
        if (this.functionCallAddresses == null) {
            this.functionCallAddresses = new HashMap<>();
        }
        for (Map.Entry<String, Function> entry : this.functionIds.entrySet()) {
            String functionId = entry.getKey();
            Function function = entry.getValue();
            ArrayList<CallGraphNode> callingNodes = this.extractAllCallingNodes(function, functionManager,
                    referenceManager);
            this.functionCalls.put(functionId, callingNodes);
        }
        IOUtils.storeCache(projectDirectory, "call", this.functionCallAddresses);

        // Get call traces for each function
        int callDepth = 4;
        for (Map.Entry<String, Function> entry : this.functionIds.entrySet()) {
            String functionId = entry.getKey();
            ArrayList<ProgramTrace> callTraces = this.extractCallTraces(functionId, callDepth);
            this.callTraces.put(functionId, callTraces);
        }
    }

    public Function getFunctionById(String functionId) {
        return this.functionIds.get(functionId);
    }

    public void setProgramArgumentEmpty(ProgramFunction fromFunction, Address calleeAddress) {
        CallGraphNode node = this.getCallGraphNode(fromFunction, calleeAddress);
        if (node == null)
            return;
        node.clearArgument();
    }

    public void setProgramArgument(ProgramFunction fromFunction, Address calleeAddress, int argumentIndex,
            CallArgument argument) {
        CallGraphNode node = this.getCallGraphNode(fromFunction, calleeAddress);

        if (node == null) {
            return;
        }

        node.addArgument(argumentIndex, argument);
    }

    public void setArgumentsAnalyzed(ProgramFunction function) {
        this.argumentsAnalyzed.put(function.getFunctionId(), true);
    }

    public boolean getArgumentsAnalyzed(ProgramFunction function) {
        return argumentsAnalyzed.containsKey(function.getFunctionId())
                && argumentsAnalyzed.get(function.getFunctionId());
    }

    public ArrayList<ProgramTrace> getCallTraces(ProgramFunction function) {
        return this.callTraces.get(function.getFunctionId());
    }

    public String getCalledFunctionId(ProgramFunction function, Address address) {
        ArrayList<CallGraphNode> nodes = this.functionCalls.get(function.getFunctionId());
        if (nodes == null || nodes.size() == 0) {
            return null;
        }

        CallGraphNode currentNode = null;
        for (CallGraphNode node : nodes) {
            if (node.getCallerAddress().compareTo(address) == 0) {
                currentNode = node;
                break;
            }
        }
        if (currentNode == null)
            return null;
        return FunctionUtils.getFunctionID(currentNode.getToFunction());
    }

    private ArrayList<ProgramTrace> extractCallTraces(String entryFunctionId, int maxDepth) {

        ArrayList<ProgramTrace> callTraces = new ArrayList<>();

        Stack<Pair<String, Integer>> unvisited = new Stack<>();
        unvisited.push(new Pair<>(entryFunctionId, 0));

        LinkedList<String> callTrace = new LinkedList<>();
        LinkedList<ProgramFunction> callTraceFunctions = new LinkedList<>();

        int lastLevel = -1;
        while (!unvisited.isEmpty()) {
            Pair<String, Integer> items = unvisited.pop();
            String functionId = items.first;
            int currentDepth = items.second;

            if (currentDepth <= maxDepth) {
                for (int i = 0; i < lastLevel - currentDepth + 1; ++i) {
                    callTrace.removeLast();
                    callTraceFunctions.removeLast();
                }
            }

            lastLevel = currentDepth;

            // Recursive cases
            if (callTrace.contains(functionId)) {
                lastLevel -= 1;
                ProgramTrace tmpTrace = new ProgramTrace(new ArrayList<>(callTrace),
                        new ArrayList<>(callTraceFunctions));
                if (!callTraces.contains(tmpTrace)) {
                    callTraces.add(tmpTrace);
                }
                continue;
            }

            callTrace.add(functionId);
            callTraceFunctions.add(this.allFunctions.get(functionId));
            // System.out.println(entryFunctionId + " -> " + functionId);
            ArrayList<CallGraphNode> nodes = this.functionCalls.get(functionId);
            if (nodes == null || nodes.size() == 0) {
                ProgramTrace tmpTrace = new ProgramTrace(new ArrayList<>(callTrace),
                        new ArrayList<>(callTraceFunctions));
                if (!callTraces.contains(tmpTrace)) {
                    callTraces.add(tmpTrace);
                }
            } else {
                if (currentDepth < maxDepth) {
                    for (CallGraphNode node : nodes) {
                        unvisited.push(new Pair<>(FunctionUtils.getFunctionID(node.getToFunction()), currentDepth + 1));
                    }
                } else {
                    ProgramTrace tmpTrace = new ProgramTrace(new ArrayList<>(callTrace),
                            new ArrayList<>(callTraceFunctions));
                    if (!callTraces.contains(tmpTrace)) {
                        callTraces.add(tmpTrace);
                    }
                }
            }
        }
        return callTraces;
    }

    private ArrayList<CallGraphNode> extractAllCallingNodes(Function function, FunctionManager functionManager,
            ReferenceManager referenceManager) {
        ArrayList<CallGraphNode> results = new ArrayList<>();

        String functionId = FunctionUtils.getFunctionID(function);
        if (this.functionCallAddresses.containsKey(functionId)) {
            ArrayList<ArrayList<Long>> callAddresses = this.functionCallAddresses
                    .get(FunctionUtils.getFunctionID(function));
            for (ArrayList<Long> tmpAddress : callAddresses) {
                Address fromAddress = this.programAnalyzer.getFlatProgramAPI().toAddr(tmpAddress.get(0));
                Address toAddress = this.programAnalyzer.getFlatProgramAPI().toAddr(tmpAddress.get(1));
                Function calleeFunction = functionManager.getFunctionAt(toAddress);
                if (calleeFunction == null) {
                    continue;
                }
                CallGraphNode node = new CallGraphNode(function, fromAddress, calleeFunction, toAddress);
                results.add(node);
            }
        } else {
            ArrayList<ArrayList<Long>> callAddresses = new ArrayList<>();

            AddressIterator referenceSourceIterator = referenceManager.getReferenceSourceIterator(function.getBody(),
                    true);
            while (referenceSourceIterator.hasNext()) {
                Address fromAddress = referenceSourceIterator.next();
                for (Reference ref : referenceManager.getFlowReferencesFrom(fromAddress)) {
                    Address toAddress = ref.getToAddress();
                    if (ref.getReferenceType().isCall()) {
                        Function calleeFunction = functionManager.getFunctionAt(toAddress);
                        if (calleeFunction == null) {
                            continue;
                        }
                        callAddresses.add(new ArrayList<>(List.of(fromAddress.getOffset(), toAddress.getOffset())));
                        CallGraphNode node = new CallGraphNode(function, fromAddress, calleeFunction, toAddress);
                        results.add(node);
                    } else {
                        System.out.println(
                                "In com.firmrec.ProgramCallGraph: extractAllCallingNodes: [Unknown Reference]");
                        System.out.println(ref);
                    }
                }
            }
            // As for MIPS
            // To-Do: Possibly applicable to all other architectures
            HighFunction highFunction = this.programAnalyzer.decompileFunction(function);
            if (highFunction != null) {
                Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOpAST pcodeOpAST = ops.next();
                    Address codeAddress = pcodeOpAST.getSeqnum().getTarget();
                    if (pcodeOpAST.getOpcode() == PcodeOp.CALL || pcodeOpAST.getOpcode() == PcodeOp.CALLIND) {
                        Varnode calledTarget = pcodeOpAST.getInput(0);
                        Address toAddress = calledTarget.getAddress();

                        Function calleeFunction = functionManager.getFunctionAt(toAddress);
                        if (calleeFunction == null) {
                            continue;
                        }
                        CallGraphNode node = new CallGraphNode(function, codeAddress, calleeFunction, toAddress);
                        if (!results.contains(node)) {
                            results.add(node);
                        }
                    }
                }
            }
            this.functionCallAddresses.put(functionId, callAddresses);
        }
        return results;
    }

    private CallGraphNode getCallGraphNode(ProgramFunction function, Address address) {
        ArrayList<CallGraphNode> nodes = this.functionCalls.get(function.getFunctionId());
        if (nodes == null || nodes.size() == 0) {
            return null;
        }

        CallGraphNode currentNode = null;
        for (CallGraphNode node : nodes) {
            if (node.getCallerAddress().compareTo(address) == 0) {
                currentNode = node;
                break;
            }
        }

        return currentNode;
    }

    public ArrayList<CallGraphNode> getCallGraphNodes(ProgramFunction fromFunction) {
        return this.functionCalls.get(fromFunction.getFunctionId());
    }

    public ArrayList<CallGraphNode> getCallGraphNodes(ProgramFunction fromFunction, ProgramFunction toFunction) {
        ArrayList<CallGraphNode> results = new ArrayList<>();
        ArrayList<CallGraphNode> nodes = this.functionCalls.get(fromFunction.getFunctionId());
        if (nodes == null || nodes.size() == 0) {
            return results;
        }

        for (CallGraphNode node : nodes) {
            if (FunctionUtils.getFunctionID(node.getToFunction()).equals(toFunction.getFunctionId())) {
                results.add(node);
            }
        }
        return results;
    }

}
