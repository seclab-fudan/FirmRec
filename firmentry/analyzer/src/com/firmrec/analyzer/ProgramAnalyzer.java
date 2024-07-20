package com.firmrec.analyzer;

import com.firmrec.analyzer.plugin.BasePlugin;
import com.firmrec.rule.FunctionArgumentDependency;
import com.firmrec.model.*;
import com.firmrec.utils.IOUtils;
import com.firmrec.utils.StringUtils;
import com.firmrec.utils.Tuple;

import generic.stl.Pair;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.prototype.analysis.AggressiveInstructionFinderAnalyzer;
import ghidra.app.util.XReferenceUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.regex.Pattern;

public class ProgramAnalyzer {
    private Program program;
    private String binaryPath;
    private BasicBlockModel basicBlockModel;
    private FlatProgramAPI flatProgramAPI;

    private ConstantPropagationAnalyzer constantPropagationAnalyzer;

    private ProgramCallGraph callGraph;
    private DecompInterface decompInterface;
    private HashMap<String, Function> functionMap;
    private HashMap<String, HighFunction> highFunctionMap;
    private HashMap<String, ProgramFunction> allFunctions;
    private HashMap<String, ProgramFunctionContext> functionContexts;
    private boolean is64;
    private boolean isARM;
    private HashMap<String, ArrayList<Long>> memoryRange;
    private HashMap<String, ProgramFunctionParameters> functionParameters;
    private ArrayList<BasePlugin> plugins;
    private HashMap<String, Register> argRegisterMap;

    private boolean funcRefStringsAnalyzed;

    public ProgramAnalyzer(Program program, FlatProgramAPI flatProgramAPI, String binaryPath, String projectDirectory) {
        this.program = program;
        this.binaryPath = binaryPath;
        this.basicBlockModel = new BasicBlockModel(this.program);

        this.decompInterface = this.setupDecompiler(this.program);
        this.decompInterface.openProgram(this.program);
        this.highFunctionMap = new HashMap<>();

        this.functionMap = new HashMap<>();
        this.allFunctions = new HashMap<>();
        this.flatProgramAPI = flatProgramAPI;
        this.constantPropagationAnalyzer = setupConstantPropagationAnalyzer(this.program);
        this.functionContexts = new HashMap<>();
        this.plugins = new ArrayList<>();
        this.argRegisterMap = new HashMap<>();
        this.funcRefStringsAnalyzed = false;

        // Extract all memory blocks
        this.memoryRange = (HashMap<String, ArrayList<Long>>) IOUtils.loadCache(projectDirectory, "memory");
        if (this.memoryRange == null) {
            this.memoryRange = new HashMap<>();
            MemoryBlock[] blocks = this.program.getMemory().getBlocks();
            for (MemoryBlock block : blocks) {
                Address minAddress = block.getStart();
                Address maxAddress = block.getEnd();
                ArrayList<Long> addressRange = new ArrayList<>();
                addressRange.add(minAddress.getOffset());
                addressRange.add(maxAddress.getOffset());
                this.memoryRange.put(block.getName(), addressRange);
            }
            IOUtils.storeCache(projectDirectory, "memory", this.memoryRange);
        }

        // Judge the architecture
        if (this.program.getLanguageID().getIdAsString().startsWith("x86")) {
            this.is64 = this.program.getDefaultPointerSize() == 8;
        } else {
            this.is64 = this.program.getLanguage().getProcessor().toString().endsWith("64");
        }
        this.isARM = this.program.getLanguage().getProcessor().toString().startsWith("ARM");

        ArrayList<Long> textMemoryRange = this.getMemoryRange().get(".text");

        // Find more instructions
        if (textMemoryRange != null) {
            Address textStart = this.flatProgramAPI.toAddr(textMemoryRange.get(0));
            Address textEnd = this.flatProgramAPI.toAddr(textMemoryRange.get(1));

            AggressiveInstructionFinderAnalyzer analyzer = new AggressiveInstructionFinderAnalyzer();
            AddressSet addressSet = flatProgramAPI.getAddressFactory().getAddressSet(textStart, textEnd);

            int disassembleTxId = this.program.startTransaction("Disassemble");
            MessageLog log = new MessageLog();

            analyzer.added(program, addressSet, this.flatProgramAPI.getMonitor(), log);
            analyzer.analysisEnded(program);
            log.write(ProgramAnalyzer.class, "InsFind");
            this.program.endTransaction(disassembleTxId, true);
        }

        /*
         * Following code are heavy
         * if (textMemoryRange != null) {
         * Address textStart = this.flatProgramAPI.toAddr(textMemoryRange.get(0));
         * Address textEnd = this.flatProgramAPI.toAddr(textMemoryRange.get(1));
         * 
         * int disassembleTxId = this.program.startTransaction("Disassemble");
         * while (textStart.compareTo(textEnd) < 0) {
         * Instruction tmpInisCstruction =
         * this.flatProgramAPI.getInstructionAt(textStart);
         * if (tmpInstruction == null) {
         * this.flatProgramAPI.disassemble(textStart);
         * }
         * textStart = textStart.add(this.isIs64() ? 8 : 4);
         * }
         * this.program.endTransaction(disassembleTxId, true);
         * }
         */

        // Create More Functions
        InstructionIterator instIterator = program.getListing().getInstructions(true);
        while (instIterator.hasNext() && !this.flatProgramAPI.getMonitor().isCancelled()) {
            Instruction instruction = instIterator.next();
            if (instruction.getFlowType() == RefType.TERMINATOR) {
                try {
                    Address funcAddr = instruction.getMaxAddress().next();
                    Function func = program.getFunctionManager().getFunctionContaining(funcAddr);
                    if (func == null) {
                        Instruction funcBeginInstr = program.getListing().getInstructionAt(funcAddr);
                        if (funcBeginInstr == null) {
                            funcBeginInstr = program.getListing().getInstructionAfter(funcAddr);
                            if (funcBeginInstr != null) {
                                funcAddr = funcBeginInstr.getAddress();
                                if (program.getFunctionManager().getFunctionContaining(funcAddr) != null) {
                                    continue;
                                }
                            }
                        }
                        if (funcBeginInstr != null) {
                            // createFunctionNear
                            PartitionCodeSubModel partitionBlockModel = new PartitionCodeSubModel(program);
                            CodeBlock[] codeBlocks = partitionBlockModel.getCodeBlocksContaining(funcAddr,
                                    this.flatProgramAPI.getMonitor());
                            if (codeBlocks.length != 1) {
                                continue;
                            }
                            Address address = codeBlocks[0].getFirstStartAddress();
                            Function newFunc = null;
                            int txId = program.startTransaction("createMoreFunc");
                            try {
                                newFunc = this.flatProgramAPI.createFunction(address, null);
                            } catch (Exception e) {
                                System.out.printf("Try to create function failed at 0x%x.\n", address.getOffset());
                            } finally {
                                program.endTransaction(txId, true);
                            }
                        }
                    }
                    // System.out.println(func);
                } catch (CancelledException e) {
                    // System.out.println("CancelledException occured.");
                }
            }
        }

        int txId = program.startTransaction("analyzeChanges");
        try {
            this.flatProgramAPI.analyzeAll(program);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            program.endTransaction(txId, true);
        }

        FunctionManager functionManager = this.program.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);

        this.functionParameters = (HashMap<String, ProgramFunctionParameters>) IOUtils.loadCache(projectDirectory,
                "parameters");
        if (this.functionParameters == null) {
            this.functionParameters = new HashMap<>();
        }
        // Get all functions
        while (functions.hasNext()) {
            Function function = functions.next();
            String functionId = FunctionUtils.getFunctionID(function);
            this.functionMap.put(functionId, function);

            ProgramCFG functionCFG = new ProgramCFG(this.flatProgramAPI, function);
            ProgramFunctionParameters parameters;
            if (this.functionParameters.containsKey(functionId)) {
                parameters = this.functionParameters.get(functionId);
            } else {
                parameters = this.analyzeProgramParameters(function);
                this.functionParameters.put(functionId, parameters);
            }

            long functionEntry = function.getEntryPoint().getOffset();
            String functionName = function.getName();
            ProgramFunction tmpFunction = new ProgramFunction(functionEntry, functionId, functionName, functionName,
                    functionCFG, parameters);
            this.allFunctions.put(functionId, tmpFunction);
        }
        IOUtils.storeCache(projectDirectory, "parameters", this.functionParameters);

        // extract call graph of program
        this.callGraph = new ProgramCallGraph(this.program, this, this.functionMap, this.allFunctions,
                projectDirectory);

        for (BasePlugin plugin : this.plugins) {
            // To-Do: May not be very elegant
            // Because of the parameter
            plugin.analyse(this);
        }
    }

    public boolean isFuncRefStringsAnalyzed() {
        return this.funcRefStringsAnalyzed;
    }

    public void setFuncRefStringsAnalyzed(boolean funcRefStringsAnalyzed) {
        this.funcRefStringsAnalyzed = funcRefStringsAnalyzed;
    }

    /**
     * Export functions to query function(s).
     */
    public ArrayList<ProgramFunction> getAllFunctions() {
        return new ArrayList<>(this.allFunctions.values());
    }

    public ArrayList<ProgramFunction> getFunctionsByName(String name, boolean regex) {
        return this.getFunctionsByName(name, regex, new ArrayList<>(this.allFunctions.values()));
    }

    public long getProgramBaseAddress() {
        return this.program.getImageBase().getOffset();
    }

    public String getProgramPath() {
        return this.binaryPath;
    }

    public ArrayList<ProgramFunction> getFunctionsByName(String name, boolean regex,
            ArrayList<ProgramFunction> waitingList) {
        ArrayList<ProgramFunction> results = new ArrayList<>();
        if (regex) {
            for (ProgramFunction function : waitingList) {
                if (Pattern.matches(name, function.getFunctionName())) {
                    results.add(function);
                }
            }
        } else {
            for (ProgramFunction function : waitingList) {
                if (function.getFunctionName().equals(name)) {
                    results.add(function);
                }
            }
        }
        return results;
    }

    public ProgramFunction getFunctionById(String functionId) {
        return this.allFunctions.get(functionId);
    }

    public ProgramFunction getFunctionById(String functionId, ArrayList<ProgramFunction> waitingList) {
        for (ProgramFunction function : waitingList) {
            if (function.getFunctionId().equals(functionId)) {
                return function;
            }
        }
        return null;
    }

    public ProgramFunction getFunctionByAddress(long address) {
        return this.getFunctionByAddress(address, new ArrayList<>(this.allFunctions.values()));
    }

    public ProgramFunction getFunctionByAddress(long address, ArrayList<ProgramFunction> waitingList) {
        for (ProgramFunction function : waitingList) {
            if (function.getAddress() == address) {
                return function;
            }
        }
        return null;
    }

    public ArrayList<ProgramFunction> getFunctionsByCalling(ProgramFunction function) {
        return this.getFunctionsByCalling(function, new ArrayList<>(this.allFunctions.values()));
    }

    public ArrayList<ProgramFunction> getFunctionsByCalling(ProgramFunction function,
            ArrayList<ProgramFunction> waitingList) {
        ArrayList<ProgramFunction> results = new ArrayList<>();

        String functionId = function.getFunctionId();
        Function calledFunction = this.callGraph.getFunctionById(functionId);

        Set<Function> callingFunctions = calledFunction.getCallingFunctions(TaskMonitor.DUMMY);
        for (Function callingFunction : callingFunctions) {
            String callingFunctionId = FunctionUtils.getFunctionID(callingFunction);
            ProgramFunction callingFunc = this.allFunctions.get(callingFunctionId);
            if (waitingList.contains(callingFunc)) {
                results.add(callingFunc);
            }
        }
        return results;
    }

    public ArrayList<ProgramFunction> getFunctionsByFlow(ArrayList<ArrayList<ProgramFunction>> flow) {
        return this.getFunctionsByFlow(flow, new ArrayList<>(this.allFunctions.values()));
    }

    public ArrayList<ProgramFunction> getFunctionsByFlow(ArrayList<ArrayList<ProgramFunction>> flow,
            ArrayList<ProgramFunction> waitingList) {
        ArrayList<ProgramFunction> results = new ArrayList<>();

        ArrayList<ArrayList<String>> functionIdsFlows = new ArrayList<>();
        for (ArrayList<ProgramFunction> currentFunctions : flow) {
            ArrayList<String> flowItems = new ArrayList<>();
            for (ProgramFunction currentFunction : currentFunctions) {
                flowItems.add(currentFunction.getFunctionId());
            }
            functionIdsFlows.add(flowItems);
        }

        for (ProgramFunction tmpFunction : waitingList) {
            ArrayList<ArrayList<String>> functionFlows = tmpFunction.getFlows();
            boolean match = false;

            for (ArrayList<String> eachFlow : functionFlows) {
                int i = 0, j = 0;
                while (i < eachFlow.size() && j < functionIdsFlows.size()) {
                    String flowItem = eachFlow.get(i);
                    if (functionIdsFlows.get(j).contains(flowItem)) {
                        i += 1;
                        j += 1;
                    } else {
                        i += 1;
                    }
                }
                if (j == functionIdsFlows.size()) {
                    match = true;
                    break;
                }
            }

            if (match) {
                results.add(tmpFunction);
            }
        }
        return results;
    }

    public ArrayList<ProgramFunction> getFunctionsBeReachedFrom(ProgramFunction function) {
        return this.getFunctionsBeReachedFrom(function, new ArrayList<>(this.allFunctions.values()));
    }

    public ArrayList<ProgramFunction> getFunctionsBeReachedFrom(ProgramFunction function,
            ArrayList<ProgramFunction> waitingList) {
        HashSet<ProgramFunction> results = new HashSet<>();
        results.add(function);

        ArrayList<ProgramTrace> callTraces = this.callGraph.getCallTraces(function);
        for (ProgramFunction currentFunction : waitingList) {
            for (ProgramTrace callTrace : callTraces) {
                if (callTrace.getTraces().contains(currentFunction.getFunctionId())) {
                    results.add(currentFunction);
                    break;
                }
            }
        }
        return new ArrayList<>(results);
    }

    public ArrayList<ProgramFunction> getFunctionsCanReachTo(ProgramFunction function) {
        return this.getFunctionsCanReachTo(function, new ArrayList<>(this.allFunctions.values()));
    }

    public ArrayList<ProgramFunction> getFunctionsCanReachTo(ProgramFunction function,
            ArrayList<ProgramFunction> waitingList) {
        HashSet<ProgramFunction> results = new HashSet<>();
        for (ProgramFunction tmpFunction : waitingList) {
            ArrayList<ProgramTrace> callTraces = this.callGraph.getCallTraces(tmpFunction);
            for (ProgramTrace callTrace : callTraces) {
                if (callTrace.getTraces().contains(function.getFunctionId())) {
                    results.add(tmpFunction);
                    break;
                }
            }
        }
        return new ArrayList<>(results);
    }

    public ArrayList<ProgramFunction> getFunctionsByArgumentsValue(String functionName, int argumentIndex, int relation,
            long argumentValue) {
        return this.getFunctionsByArgumentsValue(functionName, argumentIndex, relation, argumentValue,
                new ArrayList<>(this.allFunctions.values()));
    }

    public ArrayList<ProgramFunction> getFunctionsByArgumentsValue(String functionName, int argumentIndex, int relation,
            long argumentValue, ArrayList<ProgramFunction> waitingList) {
        ArrayList<ProgramFunction> results = new ArrayList<>();

        ArrayList<ProgramFunction> functions = this.getFunctionsByName(functionName, true);

        for (ProgramFunction function : waitingList) {
            if (!this.callGraph.getArgumentsAnalyzed(function)) {
                this.analyzeProgramCallingArguments(function);
            }
            ArrayList<CallGraphNode> nodes = new ArrayList<>();
            for (ProgramFunction toFunction : functions) {
                nodes.addAll(this.callGraph.getCallGraphNodes(function, toFunction));
            }

            for (CallGraphNode node : nodes) {
                CallArgument argument = node.getArgument(argumentIndex);
                ArrayList<Long> possibleConst = argument.getPossibleConst(0);
                if (relation == FunctionArgumentDependency.ARGUMENT_RELATION_EQ
                        && possibleConst.contains(argumentValue)) {
                    results.add(function);
                }
            }
        }
        // System.out.println(results);
        return results;
    }

    public ArrayList<ProgramFunction> getFunctionsByArgumentsType(String functionName, int argumentIndex,
            int argumentType) {
        return this.getFunctionsByArgumentsType(functionName, argumentIndex, argumentType,
                new ArrayList<>(this.allFunctions.values()));
    }

    public ArrayList<ProgramFunction> getFunctionsByArgumentsType(String functionName, int argumentIndex,
            int argumentType, ArrayList<ProgramFunction> waitingList) {
        ArrayList<ProgramFunction> results = new ArrayList<>();

        ArrayList<ProgramFunction> functions = this.getFunctionsByName(functionName, true);

        for (ProgramFunction function : waitingList) {
            if (!this.callGraph.getArgumentsAnalyzed(function)) {
                this.analyzeProgramCallingArguments(function);
            }
            ArrayList<CallGraphNode> nodes = new ArrayList<>();
            for (ProgramFunction toFunction : functions) {
                nodes.addAll(this.callGraph.getCallGraphNodes(function, toFunction));
            }

            for (CallGraphNode node : nodes) {
                System.out.println(node.getCallerAddress());
                if (argumentType == FunctionArgumentDependency.ARGUMENT_TYPE_INT_LEFT ||
                        argumentType == FunctionArgumentDependency.ARGUMENT_TYPE_INT_MULT) {
                    boolean match = false;
                    CodeBlock[] codeBlocks;
                    try {
                        codeBlocks = this.basicBlockModel.getCodeBlocksContaining(node.getCallerAddress(),
                                TaskMonitor.DUMMY);
                    } catch (CancelledException e) {
                        throw new RuntimeException(e);
                    }
                    if (codeBlocks != null) {
                        for (CodeBlock codeBlock : codeBlocks) {
                            for (Address address : codeBlock.getAddresses(true)) {
                                Instruction instruction = this.flatProgramAPI.getInstructionAt(address);
                                if (instruction == null) {
                                    continue;
                                }
                                for (PcodeOp pCode : instruction.getPcode(true)) {
                                    if ((pCode.getOpcode() == PcodeOp.INT_LEFT
                                            && argumentType == FunctionArgumentDependency.ARGUMENT_TYPE_INT_LEFT) ||
                                            (pCode.getOpcode() == PcodeOp.INT_MULT
                                                    && argumentType == FunctionArgumentDependency.ARGUMENT_TYPE_INT_MULT)) {
                                        match = true;
                                    }
                                    if (pCode.getOpcode() == PcodeOp.CALL && match
                                            && pCode.getInput(0).getAddress().equals(node.getCalleeAddress())) {
                                        results.add(function);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    CallArgument argument = node.getArgument(argumentIndex);
                    if (argument == null) {
                        continue;
                    }
                    if (argumentType == FunctionArgumentDependency.ARGUMENT_TYPE_CONST) {
                        if (argument.getArgument().isConstant()) {
                            results.add(function);
                            break;
                        }
                    } else if (argumentType == FunctionArgumentDependency.ARGUMENT_TYPE_VARIABLE) {
                        if (!argument.getArgument().isConstant()) {
                            results.add(function);
                            break;
                        }
                    }
                }
            }
        }
        return results;
    }

    /**
     * Export functions to query call sites.
     */
    public ArrayList<ProgramCallSite> getFunctionCallSites(ProgramFunction function,
            ArrayList<ProgramFunction> callings) {
        ArrayList<ProgramCallSite> results = new ArrayList<>();

        for (ProgramFunction calledFunction : callings) {
            ArrayList<CallGraphNode> nodes = this.callGraph.getCallGraphNodes(function, calledFunction);
            for (CallGraphNode node : nodes) {
                String fromFunction = node.getFromFunction().getName();
                String fromFunctionId = FunctionUtils.getFunctionID(node.getFromFunction());
                String toFunction = node.getToFunction().getName();
                String toFunctionId = FunctionUtils.getFunctionID(node.getToFunction());
                long address = node.getCallerAddress().getOffset();
                results.add(new ProgramCallSite(fromFunction, fromFunctionId,
                        toFunction, toFunctionId, address));
            }
        }

        return results;
    }

    public HashMap<ProgramCallSite, Tuple<Integer, String>> getFunctionCallSitesUsingArgument(ProgramFunction function,
            Collection<String> arguments) {
        return getFunctionCallSitesUsingArgument(function, arguments, null, 0);
    }

    public HashMap<ProgramCallSite, Tuple<Integer, String>> getFunctionCallSitesUsingArgument(ProgramFunction function,
            Collection<String> arguments, ArrayList<Integer> argumentsIndex, int argumentsCount) {
        HashMap<ProgramCallSite, Tuple<Integer, String>> results = new HashMap<>();
        if (!this.callGraph.getArgumentsAnalyzed(function)) {
            this.analyzeProgramCallingArguments(function);
        }
        ArrayList<CallGraphNode> nodes = this.callGraph.getCallGraphNodes(function);
        for (CallGraphNode node : nodes) {
            int argumentCount = node.getArgumentsCount();
            if (argumentsCount != 0 && argumentsCount != argumentCount) {
                continue;
            }
            HighFunction highToFunction = this.decompileFunction(node.getToFunction());
            // // For Tenda
            // if
            // (highToFunction.getFunctionPrototype().getReturnType().getName().equals("void"))
            // {
            // continue;
            // }
            for (int i = 0; i < argumentCount; ++i) {
                if (argumentsIndex != null && !argumentsIndex.contains(i)) {
                    continue;
                }

                CallArgument tmpArgument = node.getArgument(i);
                // System.out.println(tmpArgument);
                ArrayList<ProgramVariable> sourceVariables = tmpArgument.getSourceVariables();
                if (function.getFunctionName().equals("ej_get_web_page_name")) {
                    System.out.println(sourceVariables.size());
                }
                for (ProgramVariable variable : sourceVariables) {
                    if (function.getFunctionName().equals("ej_get_web_page_name")) {
                        System.out.println(variable.isConstant());
                    }
                    // System.out.println(variable);
                    if (variable.isConstant()) {
                        long constantValue = variable.getConstantValue();
                        if (function.getFunctionName().equals("ej_get_web_page_name")) {
                            System.out.println(constantValue);
                        }
                        String maybeString = null;
                        try {
                            Address maybeAddress = this.flatProgramAPI.toAddr(constantValue);
                            maybeString = this.getStringAt(maybeAddress);
                        } catch (Exception ignored) {

                        }

                        if (maybeString == null || maybeString.length() == 0) {
                            continue;
                        }
                        if (arguments.contains(maybeString)) {
                            String fromFunction = node.getFromFunction().getName();
                            String fromFunctionId = FunctionUtils.getFunctionID(node.getFromFunction());
                            String toFunction = node.getToFunction().getName();
                            String toFunctionId = FunctionUtils.getFunctionID(node.getToFunction());
                            long address = node.getCallerAddress().getOffset();
                            results.put(
                                    new ProgramCallSite(fromFunction, fromFunctionId, toFunction, toFunctionId,
                                            address),
                                    new Tuple<Integer, String>(i, maybeString));
                            // System.out.println(maybeString);
                            // System.out.println(node.getToFunction());
                        } else {

                        }
                        // System.out.println(constantValue);
                        // AddressSet addressSet = new AddressSet(maybeAddress);
                        // List<FoundString> foundStringList =
                        // this.flatProgramAPI.findStrings(addressSet, 2, 1, true, false);
                        // System.out.println(foundStringList);
                    }
                }
                // System.out.println(tmpArgument.getSourceVariables());
                // System.out.println(node.getArgument(i));
            }
        }
        return results;
    }

    /**
     * Export functions to query source sink traces.
     */
    public ArrayList<ProgramSourceSink> getSourcesSinksResultsInFunction(ProgramFunction function,
            HashMap<String, ArrayList<Integer>> sources, HashMap<String, ArrayList<Integer>> sinks) {
        ArrayList<ProgramSourceSink> results = new ArrayList<>();

        if (!this.callGraph.getArgumentsAnalyzed(function)) {
            this.analyzeProgramCallingArguments(function);
        }

        ProgramDDG ddg = function.getDdg();

        ArrayList<ProgramTrace> callTraces = this.getCallTraces(function);

        ArrayList<ProgramTrace> matchedTraces = new ArrayList<>();
        ArrayList<Integer> traceCalledDepth = new ArrayList<>();

        for (Map.Entry<String, ArrayList<Integer>> sinkEntry : sinks.entrySet()) {
            String sinkFunctionId = sinkEntry.getKey();
            ArrayList<Integer> sinkArguments = sinkEntry.getValue();

            for (ProgramTrace trace : callTraces) {
                if (trace.getTraces().contains(sinkFunctionId)) {
                    matchedTraces.add(trace);
                    traceCalledDepth.add(trace.getTraces().indexOf(sinkFunctionId));
                }
            }

            for (Map.Entry<String, ArrayList<Integer>> sourceEntry : sources.entrySet()) {
                String sourceFunctionId = sourceEntry.getKey();
                ArrayList<Integer> tmpSourceArguments = sourceEntry.getValue();
                for (int argumentIndex : tmpSourceArguments) {
                    // Iterate each argument of source function
                    // and select the calling node
                    for (Map.Entry<String, ArrayList<DDGNode>> nodeEntry : ddg.getAllNodes().entrySet()) {
                        DDGNode selectedNode = null;
                        ArrayList<DDGNode> callingNodes = nodeEntry.getValue();
                        for (DDGNode tmpCallingNode : callingNodes) {
                            if (Objects.equals(tmpCallingNode.getFunctionId(), sourceFunctionId) &&
                                    tmpCallingNode.getArgumentIndex() == argumentIndex) {
                                selectedNode = tmpCallingNode;
                                break;
                            }
                        }
                        if (selectedNode == null) {
                            continue;
                        }

                        // To-Do: Add more addresses
                        ArrayList<Long> sourceAddresses = new ArrayList<>();
                        sourceAddresses.add(selectedNode.getInstructionAddress());

                        for (int i = 0; i < matchedTraces.size(); ++i) {
                            ProgramTrace tmpTrace = matchedTraces.get(i);
                            int traceDepth = traceCalledDepth.get(i);

                            int currentDepth = 0;
                            ArrayList<ArrayList<DDGNode>> traceNodes = new ArrayList<>();
                            traceNodes.add(new ArrayList<>(List.of(selectedNode)));
                            ArrayList<ArrayList<String>> traceFrom = new ArrayList<>();
                            traceFrom.add(
                                    new ArrayList<>(List.of(StringUtils.convertHexString(function.getAddress(), 16))));

                            while (currentDepth < traceDepth) {
                                ArrayList<DDGNode> currentNodes = traceNodes.get(currentDepth);
                                ArrayList<String> currentFrom = traceFrom.get(currentDepth);

                                ArrayList<DDGNode> nextNodes = new ArrayList<>();
                                ArrayList<String> nextFrom = new ArrayList<>();

                                String nextCallId = tmpTrace.getTraces().get(currentDepth + 1);
                                for (int j = 0; j < currentNodes.size(); ++j) {
                                    DDGNode tmpCurrentNode = currentNodes.get(j);
                                    String tmpFromString = currentFrom.get(j);

                                    // System.out.println("---------- Begin ---------");
                                    for (DDGNode tmpFlowNode : tmpCurrentNode.getFlows()) {
                                        // System.out.println(tmpFlowNode.getInstructionAddress());
                                        if (sources.containsKey(tmpFlowNode.getFunctionId())) {
                                            break;
                                        }
                                        if (tmpFlowNode.getFunctionId() != null
                                                && tmpFlowNode.getFunctionId().equals(nextCallId)) {
                                            if (!this.callGraph
                                                    .getArgumentsAnalyzed(this.allFunctions.get(nextCallId))) {
                                                this.analyzeProgramCallingArguments(this.allFunctions.get(nextCallId));
                                            }
                                            DDGNode tmpNextNode = this.allFunctions.get(nextCallId).getDdg()
                                                    .getNode("0x0", tmpFlowNode.getArgumentIndex());
                                            if (tmpNextNode != null) {
                                                nextNodes.add(tmpNextNode);
                                            }

                                            nextFrom.add(tmpFromString + " -> " + StringUtils
                                                    .convertHexString(tmpFlowNode.getInstructionAddress(), 16));
                                        }
                                    }
                                    // System.out.println("---------- End ---------");
                                }
                                traceNodes.add(nextNodes);
                                traceFrom.add(nextFrom);
                                currentDepth += 1;
                            }

                            ArrayList<DDGNode> endNodes = traceNodes.get(traceDepth);
                            ArrayList<String> endFrom = traceFrom.get(traceDepth);

                            if (endNodes.isEmpty()) {
                                continue;
                            }

                            for (int j = 0; j < endNodes.size(); ++j) {
                                DDGNode tmpEndNode = endNodes.get(j);
                                String fromString = endFrom.get(j);

                                if (sinkArguments.contains(tmpEndNode.getArgumentIndex())) {
                                    String[] items = fromString.split("->");
                                    ArrayList<Long> callingAddress = new ArrayList<>();
                                    for (String tmpItem : items) {
                                        callingAddress.add(Long.parseLong(tmpItem.strip().substring(2), 16));
                                    }
                                    ProgramSourceSink sourceSink = new ProgramSourceSink(function.getFunctionId(),
                                            function.getAddress(), sourceAddresses, callingAddress, argumentIndex,
                                            tmpEndNode.getArgumentIndex());
                                    if (!results.contains(sourceSink)) {
                                        results.add(sourceSink);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for (ProgramSourceSink sourceSink : results) {
            System.out.println(sourceSink);
        }
        return results;
    }

    public ArrayList<ProgramSourceSink> getSourcesSinksResultsFromEntry(ProgramFunction function,
            ArrayList<Integer> sourceArguments, ArrayList<ProgramFunction> sinkFunctions,
            ArrayList<ArrayList<Integer>> sinkArguments) {
        ArrayList<ProgramSourceSink> results = new ArrayList<>();
        ArrayList<Long> sourceAddresses = new ArrayList<>();
        sourceAddresses.add(function.getAddress());

        if (!this.callGraph.getArgumentsAnalyzed(function)) {
            this.analyzeProgramCallingArguments(function);
        }

        ProgramDDG ddg = function.getDdg();

        ArrayList<ProgramTrace> callTraces = this.getCallTraces(function);

        for (int i = 0; i < sinkFunctions.size(); ++i) {
            // As for each sink function
            ArrayList<ProgramTrace> matchedTraces = new ArrayList<>();
            ArrayList<Integer> traceCalledDepth = new ArrayList<>();

            ProgramFunction tmpFunction = sinkFunctions.get(i);
            ArrayList<Integer> tmpArguments = sinkArguments.get(i);

            // Catch all traces can contain current sink function
            for (ProgramTrace trace : callTraces) {
                if (trace.getTraces().contains(tmpFunction.getFunctionId())) {
                    matchedTraces.add(trace);
                    traceCalledDepth.add(trace.getTraces().indexOf(tmpFunction.getFunctionId()));
                    break;
                }
            }

            for (int argumentIndex : sourceArguments) {
                for (int j = 0; j < matchedTraces.size(); ++j) {
                    // For each source, sink and each trace
                    // Check can source flows to sink by this trace
                    ProgramTrace tmpTrace = matchedTraces.get(j);
                    int traceDepth = traceCalledDepth.get(j);

                    int currentDepth = 0;
                    ArrayList<ArrayList<DDGNode>> traceNodes = new ArrayList<>();
                    traceNodes.add(new ArrayList<>(List.of(ddg.getNode("0x0", argumentIndex))));
                    ArrayList<ArrayList<String>> traceFrom = new ArrayList<>();
                    traceFrom.add(new ArrayList<>(List.of(StringUtils.convertHexString(function.getAddress(), 16))));

                    while (currentDepth < traceDepth) {
                        ArrayList<DDGNode> currentNodes = traceNodes.get(currentDepth);
                        ArrayList<String> currentFrom = traceFrom.get(currentDepth);

                        ArrayList<DDGNode> nextNodes = new ArrayList<>();
                        ArrayList<String> nextFrom = new ArrayList<>();

                        String nextCallId = tmpTrace.getTraces().get(currentDepth + 1);
                        for (int k = 0; k < currentNodes.size(); ++k) {
                            DDGNode tmpCurrentNode = currentNodes.get(k);
                            String tmpFromString = currentFrom.get(k);

                            for (DDGNode tmpFlowNode : tmpCurrentNode.getFlows()) {
                                if (tmpFlowNode.getFunctionId() != null
                                        && tmpFlowNode.getFunctionId().equals(nextCallId)) {
                                    if (!this.callGraph.getArgumentsAnalyzed(this.allFunctions.get(nextCallId))) {
                                        this.analyzeProgramCallingArguments(this.allFunctions.get(nextCallId));
                                    }
                                    DDGNode tmpNextNode = this.allFunctions.get(nextCallId).getDdg().getNode("0x0",
                                            tmpFlowNode.getArgumentIndex());
                                    if (tmpNextNode != null) {
                                        nextNodes.add(tmpNextNode);
                                    }

                                    nextFrom.add(tmpFromString + " -> "
                                            + StringUtils.convertHexString(tmpFlowNode.getInstructionAddress(), 16));
                                }
                            }
                        }
                        traceNodes.add(nextNodes);
                        traceFrom.add(nextFrom);
                        currentDepth += 1;
                    }

                    ArrayList<DDGNode> endNodes = traceNodes.get(traceDepth);
                    ArrayList<String> endFrom = traceFrom.get(traceDepth);

                    if (endNodes.isEmpty()) {
                        continue;
                    }

                    for (int k = 0; k < endNodes.size(); ++k) {
                        DDGNode tmpEndNode = endNodes.get(k);
                        String fromString = endFrom.get(k);
                        if (tmpArguments.contains(tmpEndNode.getArgumentIndex())) {
                            String[] items = fromString.split("->");
                            ArrayList<Long> callingAddress = new ArrayList<>();
                            for (String tmpItem : items) {
                                callingAddress.add(Long.parseLong(tmpItem.strip().substring(2), 16));
                            }
                            ProgramSourceSink sourceSink = new ProgramSourceSink(function.getFunctionId(),
                                    function.getAddress(), sourceAddresses, callingAddress, argumentIndex,
                                    tmpEndNode.getArgumentIndex());
                            if (!results.contains(sourceSink)) {
                                results.add(sourceSink);
                            }
                        }
                    }
                }
            }
        }
        return results;
    }

    /**
     * Export functions to query call traces.
     */
    public ArrayList<ProgramTrace> getCallTraces(ProgramFunction function) {
        return this.callGraph.getCallTraces(function);
    }

    /********* End *********/

    /**
     * Some other functions.
     */
    public void close() {
        this.decompInterface.closeProgram();
    }

    public void addPlugin(BasePlugin plugin) {
        this.plugins.add(plugin);
        plugin.analyse(this);
    }

    public HashMap<String, ArrayList<Long>> getMemoryRange() {
        return this.memoryRange;
    }

    public Program getProgram() {
        return this.program;
    }

    public FlatProgramAPI getFlatProgramAPI() {
        return this.flatProgramAPI;
    }

    public boolean isIs64() {
        return this.is64;
    }

    public String getStringAt(Address address) {
        ArrayList<Byte> bytes = new ArrayList<>();
        try {
            byte tmp = this.flatProgramAPI.getByte(address);
            while (tmp != 0) {
                bytes.add(tmp);
                address = address.add(1);
                tmp = this.flatProgramAPI.getByte(address);
            }
        } catch (MemoryAccessException ignored) {

        }
        byte[] rawBytes = new byte[bytes.size()];
        for (int i = 0; i < rawBytes.length; ++i) {
            rawBytes[i] = bytes.get(i);
        }
        String content = "";
        try {
            content = new String(rawBytes, "utf-8");
        } catch (UnsupportedEncodingException ignored) {

        }
        return content;
    }

    public ProgramConstant getArgumentConstant(ProgramCallSite callSite, int argumentIndex) {
        ProgramFunction callerFunction = this.allFunctions.get(callSite.getFromFunctionId());
        if (!this.callGraph.getArgumentsAnalyzed(callerFunction)) {
            this.analyzeProgramCallingArguments(callerFunction);
        }

        List<CallGraphNode> callGraphNodes = this.callGraph.getCallGraphNodes(
                getFunctionById(callSite.getFromFunctionId()),
                getFunctionById(callSite.getToFunctionId()));

        for (CallGraphNode callGraphNode : callGraphNodes) {
            if (callGraphNode.getCallerAddress().getOffset() != callSite.getAddress()) {
                continue;
            }
            CallArgument callArgument = callGraphNode.getArgument(argumentIndex);
            // handle an unexpected argument index
            return getArgumentConstant(callSite.getFromFunctionId(), callArgument);
        }
        return ProgramConstant.Unknown;
    }

    public ProgramConstant getArgumentConstant(String callerFunctionId, CallArgument callArgument) {
        if (null == callArgument)
            return ProgramConstant.Unknown;
        ProgramFunctionContext context = functionContexts.get(callerFunctionId);
        if (null == context)
            return ProgramConstant.Unknown;
        ProgramConstant constant = context.getFunctionArgumentConstants().get(callArgument);
        if (constant != null) {
            return constant;
        }
        return ProgramConstant.Unknown;
    }

    public String getConstStringArgumentAt(ProgramCallSite callSite, int argumentIndex) {
        CallArgument callArgument = getCallingArgument(callSite, argumentIndex);

        if (null == callArgument)
            return null;
        ArrayList<ProgramVariable> sourceVariables = callArgument.getSourceVariables();
        for (ProgramVariable variable : sourceVariables) {
            if (!variable.isConstant())
                continue;

            long constantValue = variable.getConstantValue();
            String maybeString = null;
            try {
                Address maybeAddress = this.flatProgramAPI.toAddr(constantValue);
                maybeString = this.getStringAt(maybeAddress);
            } catch (Exception ignored) {

            }

            if (maybeString == null || maybeString.length() == 0) {
                continue;
            }
            return maybeString;
        }

        return null;
    }

    public boolean canFunctionBeReachedFromAny(ProgramFunction function, ArrayList<ProgramFunction> functions) {
        for (ProgramFunction tmpFunction : functions) {
            ArrayList<ProgramTrace> callTraces = this.callGraph.getCallTraces(tmpFunction);
            for (ProgramTrace callTrace : callTraces) {
                if (callTrace.getTraces().contains(function.getFunctionId())) {
                    return true;
                }
            }
        }
        return false;
    }

    public BasePlugin getPlugin(int index) {
        return this.plugins.get(index);
    }

    public ProgramFunction getProgramFunction(Function function) {
        return this.allFunctions.get(FunctionUtils.getFunctionID(function));
    }

    public ProgramCallGraph getCallGraph() {
        return this.callGraph;
    }

    public ProgramFunctionParameters analyzeProgramParameters(Function function) {
        HighFunction highFunction = this.decompileFunction(function);
        if (highFunction == null) {
            return new ProgramFunctionParameters(0);
        }
        int parametersCount = highFunction.getLocalSymbolMap().getNumParams();
        return new ProgramFunctionParameters(parametersCount);
    }

    public boolean isMIPS() {
        return this.program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("MIPS"));
    }

    /**
     * Private Methods
     */

    public void analyzeFuncRefStrings() {
        if (isFuncRefStringsAnalyzed()) {
            return;
        }
        for (Data stringData : DefinedDataIterator.definedStrings(program)) {
            Object value = stringData.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            String string = (String) stringData.getValue();
            for (Reference ref : XReferenceUtils.getXReferences(stringData, -1)) {
                Address fromAddress = ref.getFromAddress();
                Function function = flatProgramAPI.getFunctionContaining(fromAddress);
                if (function == null) {
                    continue;
                }
                ProgramFunction programFunction = this.getProgramFunction(function);
                ProgramFunctionContext programContext = this.functionContexts.get(programFunction.getFunctionId());
                if (programContext == null) {
                    String functionId = programFunction.getFunctionId();
                    programContext = new ProgramFunctionContext(functionId);
                    functionContexts.put(functionId, programContext);
                }
                programContext.getRefStrings().add(new Pair<String, Long>(string, fromAddress.getOffset()));
            }
        }
        setFuncRefStringsAnalyzed(true);
    }

    public HashSet<Pair<String, Long>> getFunctionRefStrings(ProgramFunction function) {
        if (!isFuncRefStringsAnalyzed()) {
            analyzeFuncRefStrings();
        }
        ProgramFunctionContext context = this.functionContexts.get(function.getFunctionId());
        if (context == null) {
            return new HashSet<>();
        }
        return context.getRefStrings();
    }

    /**
     * To-Do: We suppose that the register or stack varnode without Def Op
     * is from parameters of current function
     */
    private ProgramVariable analyzeVariable(Varnode varnode, ProgramFunctionContext context, int parameterCount) {
        HashMap<Varnode, Varnode> varnodeParents = new HashMap<>();

        LinkedList<Varnode> workList = new LinkedList<>();
        workList.offer(varnode);

        int beginIndex = this.is64 ? 8 : 4; // To-Do: should be determined dynamically
        while (!workList.isEmpty()) {
            Varnode curVarnode = workList.poll();
            PcodeOp defOp = curVarnode.getDef();

            ProgramVariable curVariable;
            if (context.getVariable(curVarnode) != null) {
                curVariable = context.getVariable(curVarnode);
                if (varnodeParents.containsKey(curVarnode)) {
                    context.getVariable(varnodeParents.get(curVarnode)).addDependency(curVariable);
                }
                continue;
            } else {
                curVariable = new ProgramVariable(curVarnode);
                context.addVariable(curVarnode, curVariable);

                if (curVarnode.isConstant()) {
                    curVariable.setConstantValue(curVarnode.getOffset());
                } else if (curVarnode.isRegister()) {
                    this.extractParameterRegisters();
                    // System.out.println(curVarnode);
                    String registerName = "unknown0";
                    if (this.program.getRegister(curVarnode) != null) {
                        registerName = this.program.getRegister(curVarnode).getName();
                    }
                    curVariable.setRegisterIndex(registerName);
                    if (defOp == null && this.extractParameterRegisters().containsKey(registerName)) {
                        int tmpParameterIndex = this.extractParameterRegisters().get(registerName);
                        if (tmpParameterIndex < parameterCount) {
                            curVariable.setParameter(true);
                            curVariable.setParameterIndex(tmpParameterIndex);
                        }
                    }
                } else if (curVarnode.getAddress().getAddressSpace().isStackSpace()) {
                    int stackOffset = (int) curVarnode.getOffset();
                    int stackWidth = curVarnode.getSize();
                    curVariable.setStackOffset(stackOffset);
                    if (defOp == null && stackOffset > 0) {
                        int tmpParameterIndex = beginIndex + stackOffset / stackWidth;
                        if (tmpParameterIndex < parameterCount) {
                            curVariable.setParameter(true);
                            curVariable.setParameterIndex(tmpParameterIndex);
                        }
                    }
                } else if (curVarnode.getAddress().isMemoryAddress()) {
                    curVariable.setMemoryValue(curVarnode.getOffset());
                } else if (curVarnode.isUnique()) {
                    curVariable.setUniqueValue(curVarnode.getOffset());
                } else if (curVarnode.getAddress().isVariableAddress()) {
                    curVariable.setVariableValue(curVarnode.getOffset());
                } else {
                    System.out.println("????????");
                    System.out.println(curVarnode);
                    System.out.println(curVarnode.getAddress().getAddressSpace().getName());
                }
            }

            if (varnodeParents.containsKey(curVarnode)) {
                context.getVariable(varnodeParents.get(curVarnode)).addDependency(curVariable);
            }

            // Get all dependencies
            if (defOp == null) {
                continue;
            }

            curVariable.setVariableFromOp(defOp.getOpcode());
            if (defOp.getOpcode() == PcodeOp.CALL) {
                curVariable.setCallAddress(defOp.getSeqnum().getTarget().getOffset());
            }

            for (Varnode sourceVarnode : defOp.getInputs()) {
                workList.offer(sourceVarnode);
                varnodeParents.put(sourceVarnode, curVarnode);
            }
        }

        return context.getVariable(varnode);
    }

    public HashMap<String, Integer> extractParameterRegisters() {
        HashMap<String, Integer> results = new HashMap<>();

        Language language = this.program.getLanguage();
        Processor processor = language.getProcessor();

        if (processor.equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
            if (this.isIs64()) {
                return new HashMap<>(Map.of(
                        "RDI", 0,
                        "RSI", 1,
                        "RDX", 2,
                        "RCX", 3,
                        "R8", 4,
                        "R9", 5,
                        "EDI", 0,
                        "ESI", 1,
                        "EDX", 2,
                        "ECX", 4));
            } else {
                // return new HashMap<>(Map.of(""));
            }
            System.out.println("Meet X86!" + this.isIs64());
        } else if (processor.equals(Processor.findOrPossiblyCreateProcessor("ARM"))) {
            if (this.isIs64()) {
                for (int i = 0; i < 8; ++i) {
                    results.put("x" + i, i);
                    results.put("w" + i, i);
                }
                return results;
            } else {
                return new HashMap<>(Map.of("r0", 0, "r1", 1, "r2", 2, "r3", 3));
            }
        } else if (processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS"))) {
            return new HashMap<>(Map.of("a0", 0, "a1", 1, "a2", 2, "a3", 3));
        }
        return results;
    }

    private CallArgument analyzeArgument(Address callAddress, int argumentIndex, Varnode argument,
            ProgramFunctionContext context,
            int parameterCount) {
        CallArgument result = new CallArgument(callAddress, argumentIndex, argument);
        ProgramVariable variable = this.analyzeVariable(argument, context, parameterCount);
        result.setVariable(variable);
        return result;
    }

    public CallArgument getCallingArgument(ProgramCallSite callSite, int argumentIndex) {
        List<CallGraphNode> callGraphNodes = this.callGraph.getCallGraphNodes(
                getFunctionById(callSite.getFromFunctionId()),
                getFunctionById(callSite.getToFunctionId()));

        ProgramFunction callerFunction = this.allFunctions.get(callSite.getFromFunctionId());
        this.analyzeProgramCallingArguments(callerFunction);

        // Get argument
        CallArgument callArgument = null;
        for (CallGraphNode callGraphNode : callGraphNodes) {
            if (callGraphNode.getCallerAddress().getOffset() != callSite.getAddress()) {
                continue;
            }
            callArgument = callGraphNode.getArgument(argumentIndex);
            break;
        }
        return callArgument;
    }

    public void analyzeProgramCallingArguments(ProgramFunction function) {
        // Already analyzed this function
        if (this.callGraph.getArgumentsAnalyzed(function)) {
            return;
        }
        // Analyze arguments of one function
        String functionId = function.getFunctionId();

        HighFunction highFunction = this.decompileFunction(this.functionMap.get(functionId));
        if (highFunction == null)
            return;

        // Initialize the context
        ProgramFunctionContext context = functionContexts.get(functionId);
        if (context == null) {
            context = new ProgramFunctionContext(functionId);
            functionContexts.put(functionId, context);
        }
        ProgramDDG ddg = new ProgramDDG(function);

        HashMap<String, ArrayList<DDGNode>> otherAddressNode = new HashMap<>();

        SymbolicPropogator symEval = propConstantInFunction(context, function);

        Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST pcodeOpAST = ops.next();
            Address codeAddress = pcodeOpAST.getSeqnum().getTarget();
            if (pcodeOpAST.getOpcode() == PcodeOp.CALL || pcodeOpAST.getOpcode() == PcodeOp.CALLIND) {
                String calledFunctionId = this.callGraph.getCalledFunctionId(function, codeAddress);
                Function calledFunctionModel = this.functionMap.get(calledFunctionId);
                String callingId = FunctionUtils.getCallingId(codeAddress.getOffset(), calledFunctionId);

                int argumentsCount = pcodeOpAST.getNumInputs() - 1;
                if (argumentsCount == 0) {
                    this.callGraph.setProgramArgumentEmpty(function, codeAddress);
                    this.callGraph.setArgumentsAnalyzed(function);
                } else {
                    for (int argumentIndex = 0; argumentIndex < argumentsCount; ++argumentIndex) {
                        Varnode argVarnode = pcodeOpAST.getInput(argumentIndex + 1);

                        DDGNode tmpNode = new DDGNode(codeAddress.getOffset(), calledFunctionId, argumentIndex);

                        CallArgument tmpArgument = this.analyzeArgument(codeAddress, argumentIndex, argVarnode, context,
                                function.getParametersCount());
                        context.addFunctionArguments(callingId, argumentIndex, tmpArgument);

                        // analyze constant argument
                        ProgramConstant constant = null;
                        if (calledFunctionModel != null) {
                            Parameter parameter = calledFunctionModel.getParameter(argumentIndex);
                            Register argRegister;
                            if (parameter != null) {
                                argRegister = parameter.getRegister();
                            } else {
                                argRegister = getArgRegister(argumentIndex, calledFunctionModel.getCallingConvention());
                            }

                            if (argRegister != null) {
                                constant = this.analyzeArgumentConstant(symEval, codeAddress,
                                        argRegister);
                                if (constant != null) {
                                    context.addFunctionArgumentConstants(tmpArgument, constant);
                                }
                            }
                        }

                        if (constant != null && (constant.isAddr() || constant.isRelArg())) {
                            String constantKey = constant.toString();
                            if (!otherAddressNode.containsKey(constant.toString())) {
                                otherAddressNode.put(constantKey, new ArrayList<>());
                            }
                            otherAddressNode.get(constantKey).add(tmpNode);
                        }

                        // for (ProgramVariable tmpVariable : tmpArgument.getSourceVariables()) {
                        // if (tmpVariable.isConstant()) {
                        // long constantValue = tmpVariable.getConstantValue();
                        // String constantKey = StringUtils.convertHexString(constantValue, 16);
                        // if (constantValue >= this.program.getMinAddress().getOffset() &&
                        // constantValue <= this.program.getMaxAddress().getOffset()) {
                        // if (!otherAddressNode.containsKey(constantKey)) {
                        // otherAddressNode.put(constantKey, new ArrayList<>());
                        // }
                        // otherAddressNode.get(constantKey).add(tmpNode);
                        // }
                        // }
                        // }

                        ddg.addNode(codeAddress.getOffset(), calledFunctionId, tmpNode);
                        this.callGraph.setProgramArgument(function, codeAddress, argumentIndex, tmpArgument);
                    }

                    this.callGraph.setArgumentsAnalyzed(function);
                }
                Varnode outVarnode = pcodeOpAST.getOutput();
                if (outVarnode != null) {
                    ProgramVariable outVariable = this.analyzeVariable(outVarnode, context,
                            function.getParametersCount());
                    context.addVariableFromCalling(outVariable, callingId);

                    // -1 means the return value
                    DDGNode tmpNode = new DDGNode(codeAddress.getOffset(), calledFunctionId, -1);
                    ddg.addNode(codeAddress.getOffset(), calledFunctionId, tmpNode);
                }
            }
        }

        // Heuristic: remove unlikely output pointer
        for (Map.Entry<String, ArrayList<DDGNode>> entry : otherAddressNode.entrySet()) {
            Set<String> visited = new HashSet<>();
            boolean invalid = false;
            for (DDGNode ddgNode : entry.getValue()) {
                String key = ddgNode.getFunctionId() + "@" + ddgNode.getArgumentIndex();
                if (visited.contains(key)) {
                    invalid = true;
                    break;
                }
                visited.add(key);
            }
            if (invalid) {
                entry.getValue().clear();
            }
        }

        for (Map.Entry<CallArgument, Pair<String, Integer>> entry : context.getFunctionArguments().entrySet()) {
            CallArgument tmpArgument = entry.getKey();
            Pair<String, Integer> callItems = entry.getValue();
            String callingId = callItems.first;
            int argumentIndex = callItems.second;
            ArrayList<ProgramVariable> sourceVariables = tmpArgument.getSourceVariables();

            DDGNode ddgNode = ddg.getNode(callingId, argumentIndex);
            ProgramConstant constant = context.getFunctionArgumentConstant(tmpArgument);
            if (constant != null && (constant.isAddr() || constant.isRelArg())) {
                String constantKey = constant.toString();
                for (DDGNode maybeFromNode : otherAddressNode.get(constantKey)) {
                    if (maybeFromNode.getInstructionAddress() < ddgNode.getInstructionAddress()) {
                        maybeFromNode.addFlowTo(ddgNode);
                    }
                }
            }

            for (ProgramVariable tmpVariable : sourceVariables) {
                if (tmpVariable.isParameter()) {
                    DDGNode fromNode = ddg.getNode("0x0", tmpVariable.getParameterIndex());
                    fromNode.addFlowTo(ddgNode);
                    continue;
                }

                // Flow from return values of other functions
                for (String fromCallingId : context.getCallingIdsFromOutput(tmpVariable)) {
                    if (fromCallingId != null) {
                        DDGNode fromNode = ddg.getNode(fromCallingId, -1);
                        fromNode.addFlowTo(ddgNode);
                        continue;
                    }

                    // if (tmpVariable.isConstant()) {
                    // String constantValue =
                    // StringUtils.convertHexString(tmpVariable.getConstantValue(), 16);
                    // if (otherAddressNode.get(constantValue) != null
                    // && otherAddressNode.get(constantValue).size() > 1) {
                    // for (DDGNode maybeFromNode : otherAddressNode.get(constantValue)) {
                    // if (maybeFromNode.getInstructionAddress() < ddgNode.getInstructionAddress())
                    // {
                    // maybeFromNode.addFlowTo(ddgNode);
                    // }
                    // }
                    // }
                    // }
                }

                // Flow from pointer variables
                if (tmpArgument.getVariable().getVariableFromOp() == PcodeOp.PTRSUB ||
                        tmpArgument.getVariable().getVariableFromOp() == PcodeOp.PTRADD) {
                    for (Pair<String, Integer> inputItem : context.getCallingItemsFromInput(tmpVariable)) {
                        String fromCallingId = inputItem.first;
                        if (fromCallingId.equals(callingId))
                            continue;
                        // Heuristic: cut flow by address
                        long fromCallingAddress = FunctionUtils.getCallingAddress(fromCallingId);
                        if (fromCallingAddress >= ddgNode.getInstructionAddress())
                            continue;
                        int fromArgumentIndex = inputItem.second;
                        DDGNode fromNode = ddg.getNode(fromCallingId, fromArgumentIndex);
                        fromNode.addFlowTo(ddgNode);
                    }
                }
            }
        }

        function.setDdg(ddg);
        this.functionContexts.put(functionId, context);
    }

    public ArrayList<Pair<Long, ProgramConstant>> analyzeCallingArgumentRelatedConstants(ProgramCallSite callSite,
            int argumentIndex) {
        ArrayList<Pair<Long, ProgramConstant>> constants = new ArrayList<>();
        ProgramFunctionContext context = this.functionContexts.get(callSite.getFromFunctionId());
        if (context == null)
            return constants;
        SymbolicPropogator symEval = context.getConstSymEval();

        // Get argument
        CallArgument callArgument = getCallingArgument(callSite, argumentIndex);
        if (callArgument == null)
            return constants;

        String fromFunctionId = callSite.getFromFunctionId();
        HighFunction highFunction = this.decompileFunction(this.functionMap.get(fromFunctionId));
        if (highFunction == null)
            return constants;

        Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
        int count = -1;
        while (ops.hasNext()) {
            // analyze nearby constants only
            if (count >= 20)
                break;
            PcodeOpAST pcodeOpAST = ops.next();
            int pcodeOp = pcodeOpAST.getOpcode();
            Address codeAddress = pcodeOpAST.getSeqnum().getTarget();
            if (pcodeOp == PcodeOp.CALL || pcodeOp == PcodeOp.CALLIND) {
                if (codeAddress.getOffset() == callSite.getAddress()) {
                    count = 0;
                    continue;
                }
            }

            if (count == -1)
                continue;

            if (pcodeOp == PcodeOp.INT_EQUAL || pcodeOp == PcodeOp.INT_NOTEQUAL) {
                Pair<Varnode, ProgramConstant> pair = analyzeCmpConstant(symEval, pcodeOpAST);
                if (pair == null)
                    continue;
                ProgramConstant constant = pair.second;
                // HACK: ignore data dependencies
                // Varnode varnode = pair.first;
                // ProgramVariable variable = context.getVariable(varnode);
                // if (variable == null)
                // continue;
                // if (variable.containsDependency(callArgument.getVariable())) {
                // constants.add(new Pair<Long, ProgramConstant>(codeAddress.getOffset(),
                // constant));
                // }
                if (constant.isInt()) {
                    long value = constant.getIntValue();
                    if (Math.abs(value) <= 0x1000 || Long.bitCount(value) < 5 || Long.bitCount(value + 1) < 5
                            || value % 100 == 0)
                        continue;
                    constants.add(new Pair<Long, ProgramConstant>(codeAddress.getOffset(), constant));
                }
            }

            count += 1;
        }

        return constants;
    }

    private Pair<Varnode, ProgramConstant> analyzeCmpConstant(SymbolicPropogator symEval, PcodeOpAST pcodeOpAST) {
        Address address = pcodeOpAST.getSeqnum().getTarget();
        int pcodeOp = pcodeOpAST.getOpcode();
        if (pcodeOp != PcodeOp.INT_EQUAL && pcodeOp != PcodeOp.INT_NOTEQUAL)
            return null;
        Varnode varnodes[] = { pcodeOpAST.getInput(0), pcodeOpAST.getInput(1) };
        long value;
        for (Varnode varnode : varnodes) {
            if (varnode.isConstant()) {
                value = varnode.getOffset();
            } else if (varnode.isRegister()) {
                Register reg = this.program.getRegister(varnode);
                if (reg == null)
                    continue;
                SymbolicPropogator.Value val = symEval.getRegisterValue(address, reg);
                if (val == null)
                    continue;
                if (val.isRegisterRelativeValue())
                    continue;
                value = val.getValue();
            } else {
                continue;
            }
            return new Pair<Varnode, ProgramConstant>(varnode, ProgramConstant.createInt(value));
        }
        return null;
    }

    public Register getArgRegister(int index, PrototypeModel convention) {
        String conventionName = "";
        if (convention != null) {
            conventionName = convention.getName();
        }
        String key = conventionName + "_" + index;

        if (argRegisterMap.containsKey(key)) {
            return argRegisterMap.get(key);
        }

        if (convention == null) {
            CompilerSpec spec = program.getCompilerSpec();
            convention = spec.getDefaultCallingConvention();
        }
        Register reg = convention.getArgLocation(index, null, null, program).getRegister();
        argRegisterMap.put(key, reg);
        return reg;
    }

    private ConstantPropagationAnalyzer setupConstantPropagationAnalyzer(Program program) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        List<ConstantPropagationAnalyzer> analyzers = ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
        for (ConstantPropagationAnalyzer analyzer : analyzers) {
            if (analyzer.canAnalyze(program)) {
                return (ConstantPropagationAnalyzer) mgr.getAnalyzer(analyzer.getName());
            }
        }
        return null;
    }

    private SymbolicPropogator propConstantInFunction(ProgramFunctionContext context, ProgramFunction function) {
        Function ghidraFunction = functionMap.get(function.getFunctionId());
        if (context.getConstSymEval() != null) {
            return context.getConstSymEval();
        }
        try {
            int flowConstantTxId = this.program.startTransaction("flowConstant");
            SymbolicPropogator symEval = new SymbolicPropogator(program);
            symEval.setParamRefCheck(true);
            symEval.setReturnRefCheck(true);
            symEval.setStoredRefCheck(true);
            this.constantPropagationAnalyzer.flowConstants(program, ghidraFunction.getEntryPoint(),
                    ghidraFunction.getBody(),
                    symEval, TaskMonitor.DUMMY);
            this.program.endTransaction(flowConstantTxId, true);
            context.setConstSymEval(symEval);
            return symEval;
        } catch (CancelledException e) {
            return null;
        }
    }

    private ProgramConstant analyzeArgumentConstant(SymbolicPropogator symEval, Address callingAddress,
            Register argRegister) {
        Address nextAddr = movePastDelaySlot(callingAddress);
        SymbolicPropogator.Value val = symEval.getRegisterValue(nextAddr, argRegister);
        if (val == null)
            return ProgramConstant.Unknown;
        long value = val.getValue();

        try {
            MemoryBlock memoryBlock;
            Address refAddress = null;
            try {
                refAddress = this.flatProgramAPI.toAddr(value);
                memoryBlock = this.flatProgramAPI.getMemoryBlock(refAddress);
            } catch (Exception e) {
                memoryBlock = null;
            }
            if (memoryBlock != null) {
                String foundString = this.getStringAt(refAddress);
                // check most part of foundString is printable
                if (foundString != null && foundString.length() > 0) {
                    int printableCount = 0;
                    for (int i = 0; i < foundString.length(); i++) {
                        char ch = foundString.charAt(i);
                        if (ch >= 0x20 && ch <= 0x7e) {
                            printableCount++;
                        }
                    }
                    if (printableCount > foundString.length() * 0.8) {
                        return ProgramConstant.createString(foundString);
                    }
                }
            }
        } catch (Exception e) {
            return ProgramConstant.createAddr(value);
        }
        if (val.isRegisterRelativeValue())
            return ProgramConstant.createRelArg(val.getRelativeRegister().getName(), value);
        return ProgramConstant.createInt(value);
    }

    private Address movePastDelaySlot(Address addr) {
        Instruction inst = flatProgramAPI.getInstructionAt(addr);
        if (inst == null)
            return addr;
        if (inst.getDelaySlotDepth() > 0) {
            do {
                if (inst.getNext() == null)
                    break;
                inst = inst.getNext();
            } while (inst.isInDelaySlot());
        }
        return inst.getAddress();
    }

    private DecompInterface setupDecompiler(Program program) {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options = new DecompileOptions();
        decompInterface.setOptions(options);
        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        return decompInterface;
    }

    public HighFunction decompileFunction(Function function) {
        if (function == null)
            return null;
        HighFunction highFunction;
        String functionId = FunctionUtils.getFunctionID(function);
        if (!this.highFunctionMap.containsKey(functionId)) {
            Function tmpFunction = this.functionMap.get(functionId);
            try {
                DecompileResults decompileResults = this.decompInterface.decompileFunction(tmpFunction,
                        this.decompInterface.getOptions().getDefaultTimeout(), TaskMonitor.DUMMY);
                highFunction = decompileResults.getHighFunction();
            } catch (NullPointerException ignore) {
                // I don't figure out why this happens
                return null;
            }
            this.highFunctionMap.put(functionId, highFunction);
        } else {
            highFunction = this.highFunctionMap.get(functionId);
        }
        return highFunction;
    }

    public HighFunction decompileFunction(ProgramFunction function) {
        return this.decompileFunction(this.functionMap.get(function.getFunctionId()));
    }

    public Function getRawFunction(ProgramFunction function) {
        return this.functionMap.get(function.getFunctionId());
    }
}
