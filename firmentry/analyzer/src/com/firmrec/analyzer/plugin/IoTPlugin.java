package com.firmrec.analyzer.plugin;

import com.firmrec.analyzer.*;
import com.firmrec.model.ProgramCallSite;
import com.firmrec.model.ProgramConstant;
import com.firmrec.model.ProgramFunction;
import com.firmrec.model.ProgramVariable;
import com.firmrec.storage.InputStorage;
import com.firmrec.utils.StringUtils;
import com.firmrec.utils.Tuple;

import generic.stl.Pair;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.lang.invoke.CallSite;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.util.*;
import java.util.Map.Entry;

public class IoTPlugin implements BasePlugin {

    private HashMap<String, Address> strings;
    private HashMap<String, Function> namedFunctions;
    private HashMap<String, Function> functionIds;
    private HashMap<String, ProgramFunction> allFunctions;

    public IoTPlugin() {
        super();
        this.strings = new HashMap<>();
        this.namedFunctions = new HashMap<>();
        this.functionIds = new HashMap<>();
        this.allFunctions = new HashMap<>();
    }

    @Override
    public void analyse(ProgramAnalyzer analyzer) {
        Program program = analyzer.getProgram();
        FlatProgramAPI flatProgramAPI = analyzer.getFlatProgramAPI();

        if (analyzer.getMemoryRange().containsKey("ram")) {
            // RTOS
            System.out.println("RTOS");
            ArrayList<Long> memoryRange = analyzer.getMemoryRange().get("ram");
            Address startAddress = analyzer.getFlatProgramAPI().toAddr(memoryRange.get(0));
            Address endAddress = analyzer.getFlatProgramAPI().toAddr(memoryRange.get(1));

            while (startAddress.compareTo(endAddress) < 0) {
                try {
                    ArrayList<Byte> bytes = new ArrayList<>();
                    Address baseAddress = startAddress;
                    byte tmp = analyzer.getFlatProgramAPI().getByte(startAddress);
                    while (tmp == 10 || (tmp >= 32 && tmp <= 126)) {
                        bytes.add(tmp);
                        startAddress = startAddress.add(1);
                        tmp = analyzer.getFlatProgramAPI().getByte(startAddress);
                    }
                    startAddress = startAddress.add(1);
                    if (tmp == 0) {
                        byte[] rawBytes = new byte[bytes.size()];
                        for (int i = 0; i < rawBytes.length; ++i) {
                            rawBytes[i] = bytes.get(i);
                        }
                        String content = "";
                        try {
                            content = new String(rawBytes, "utf-8");
                        } catch (UnsupportedEncodingException ignored) {

                        }
                        if (content.length() > 0 && StringUtils.isASCIIString(content)) {
                            this.strings.put(content, baseAddress);
                        }
                    }
                } catch (MemoryAccessException ignored) {
                    startAddress = startAddress.add(1);
                }
            }
        } else {
            // Linux
            System.out.println("Linux");
            ArrayList<Long> memoryRange = analyzer.getMemoryRange().get(".data");
            if (memoryRange != null) {
                Address startAddress = analyzer.getFlatProgramAPI().toAddr(memoryRange.get(0));
                Address endAddress = analyzer.getFlatProgramAPI().toAddr(memoryRange.get(1));
                ArrayList<Long> textMemoryRange = analyzer.getMemoryRange().get(".text");
                Address textStart = analyzer.getFlatProgramAPI().toAddr(textMemoryRange.get(0));
                Address textEnd = analyzer.getFlatProgramAPI().toAddr(textMemoryRange.get(1));
                while (startAddress.compareTo(endAddress) < 0) {
                    int maybePointer = 0;
                    Function function = null;
                    boolean maybeMissFunction = false;
                    try {
                        maybePointer = flatProgramAPI.getInt(startAddress);
                        function = flatProgramAPI.getFunctionAt(flatProgramAPI.toAddr(maybePointer));

                        if (function == null && maybePointer >= textStart.getOffset()
                                && maybePointer <= textEnd.getOffset()) {
                            maybeMissFunction = true;
                        }
                    } catch (MemoryAccessException ignored) {
                    }

                    if (function != null || maybeMissFunction) {
                        try {
                            int stringAddress = flatProgramAPI.getInt(startAddress.subtract(analyzer.isIs64() ? 8 : 4));
                            String maybeString = analyzer.getStringAt(flatProgramAPI.toAddr(stringAddress));
                            if (maybeString != null && maybeString.length() > 0
                                    && StringUtils.isASCIIString(maybeString)) {
                                if (function != null) {
                                    this.namedFunctions.put(maybeString, function);
                                } else {
                                }
                            }
                        } catch (MemoryAccessException ignored) {
                        }
                    }
                    startAddress = startAddress.add(analyzer.isIs64() ? 8 : 4);
                }
            }

            ArrayList<String> strSearchRangeNames = new ArrayList<>();
            memoryRange = analyzer.getMemoryRange().get(".rodata");
            if (memoryRange == null) {
                // aggressive find strings
                strSearchRangeNames.addAll(analyzer.getMemoryRange().keySet());
            } else {
                strSearchRangeNames.add(".rodata");
            }
            for (String strSearchRangeName : strSearchRangeNames) {
                memoryRange = analyzer.getMemoryRange().get(strSearchRangeName);
                Address startAddress = analyzer.getFlatProgramAPI().toAddr(memoryRange.get(0));
                Address endAddress = analyzer.getFlatProgramAPI().toAddr(memoryRange.get(1));

                while (startAddress.compareTo(endAddress) < 0) {
                    try {
                        ArrayList<Byte> bytes = new ArrayList<>();
                        Address baseAddress = startAddress;
                        byte tmp = analyzer.getFlatProgramAPI().getByte(startAddress);
                        while (tmp == 10 || (tmp >= 32 && tmp <= 126)) {
                            bytes.add(tmp);
                            startAddress = startAddress.add(1);
                            tmp = analyzer.getFlatProgramAPI().getByte(startAddress);
                        }
                        startAddress = startAddress.add(1);
                        if (tmp == 0) {
                            byte[] rawBytes = new byte[bytes.size()];
                            for (int i = 0; i < rawBytes.length; ++i) {
                                rawBytes[i] = bytes.get(i);
                            }
                            String content = "";
                            try {
                                content = new String(rawBytes, "utf-8");
                            } catch (UnsupportedEncodingException ignored) {

                            }
                            if (content.length() > 0 && StringUtils.isASCIIString(content)) {
                                this.strings.put(content, baseAddress);
                            }
                        }
                    } catch (MemoryAccessException ignored) {
                        startAddress = startAddress.add(1);
                    }
                }
            }
        }
    }

    @Deprecated
    public void extractPoCInformation(ProgramAnalyzer analyzer, String targetURL, HashMap<String, String> parameters,
            String outputPath) {

        ProgramFunction targetFunction = null;
        ArrayList<ProgramFunction> maybeTargetFunctions = new ArrayList<>();
        String[] targetUrlItems = targetURL.split("/");
        String targetURLItem = targetUrlItems[targetUrlItems.length - 1];

        ArrayList<ProgramFunction> allFunctions = analyzer.getAllFunctions();

        // Filter function by name
        if (this.namedFunctions.containsKey(targetURL)) {
            targetFunction = analyzer.getProgramFunction(this.namedFunctions.get(targetURL));
            maybeTargetFunctions.add(targetFunction);
        }

        if (this.namedFunctions.containsKey(targetURLItem)) {
            targetFunction = analyzer.getProgramFunction(this.namedFunctions.get(targetURLItem));
            if (!maybeTargetFunctions.contains(targetFunction)) {
                maybeTargetFunctions.add(targetFunction);
            }
        }

        // Get functions by register
        for (ProgramFunction tmpFunction : allFunctions) {
            HashMap<ProgramCallSite, Tuple<Integer, String>> callSites = analyzer
                    .getFunctionCallSitesUsingArgument(tmpFunction, new ArrayList<>(List.of(targetURL, targetURLItem)));
            for (ProgramCallSite tmpCallSite : callSites.keySet()) {
                ArrayList<CallGraphNode> tmpNodes = analyzer.getCallGraph().getCallGraphNodes(tmpFunction,
                        analyzer.getFunctionById(tmpCallSite.getToFunctionId()));
                for (CallGraphNode tmpNode : tmpNodes) {
                    if (tmpNode.getCallerAddress().getOffset() != tmpCallSite.getAddress())
                        continue;
                    for (int i = 0; i < tmpNode.getArgumentsCount(); ++i) {
                        CallArgument tmpArgument = tmpNode.getArgument(i);
                        ArrayList<ProgramVariable> sourceVariables = tmpArgument.getSourceVariables();
                        for (ProgramVariable sourceVariable : sourceVariables) {
                            if (sourceVariable.isConstant()) {
                                Address tmpAddress = analyzer.getFlatProgramAPI()
                                        .toAddr(sourceVariable.getConstantValue());
                                Function maybeFunction = analyzer.getFlatProgramAPI().getFunctionAt(tmpAddress);
                                if (maybeFunction != null) {
                                    maybeTargetFunctions.add(analyzer.getFunctionByAddress(tmpAddress.getOffset()));
                                }
                            }
                        }
                    }
                }
            }
        }

        JSONObject outputResult = new JSONObject();
        outputResult.put("Base Address", analyzer.getProgramBaseAddress());
        outputResult.put("Path", analyzer.getProgramPath());
        JSONArray finalResults = new JSONArray();
        ArrayList<String> mayBeArguments = new ArrayList<>(parameters.keySet());
        for (ProgramFunction tmpMaybeTargetFunction : maybeTargetFunctions) {
            JSONObject tmpResult = new JSONObject();

            if (analyzer.isMIPS()) {
                Function tmpRawFunction = analyzer.getRawFunction(tmpMaybeTargetFunction);

                Register t9Register = analyzer.getProgram().getRegister("t9");
                RegisterValue t9Value = analyzer.getProgram().getProgramContext().getRegisterValue(t9Register,
                        tmpRawFunction.getEntryPoint());
                if (t9Value != null) {
                    tmpResult.put("t9", t9Value.getSignedValue());
                } else {
                    tmpResult.put("t9", 0);
                }

                Register gpRegister = analyzer.getProgram().getRegister("gp");
                RegisterValue gpValue = analyzer.getProgram().getProgramContext().getRegisterValue(gpRegister,
                        tmpRawFunction.getEntryPoint());
                if (gpValue != null) {
                    tmpResult.put("gp", gpValue.getSignedValue());
                } else {
                    tmpResult.put("gp", 0);
                }
            }

            tmpResult.put("Address", tmpMaybeTargetFunction.getAddress());
            tmpResult.put("Name", tmpMaybeTargetFunction.getFunctionName());
            tmpResult.put("Judgement", "Name");
            tmpResult.put("Confidence", 1.0);

            // // Tenda
            // HashMap<ProgramCallSite, String> callSites =
            // analyzer.getFunctionCallSitesUsingArgument(tmpMaybeTargetFunction,
            // mayBeArguments, new ArrayList<>(List.of(1)), 3);
            HashMap<ProgramCallSite, Tuple<Integer, String>> callSites = analyzer
                    .getFunctionCallSitesUsingArgument(tmpMaybeTargetFunction, mayBeArguments, null, 0);
            JSONArray tmpSources = new JSONArray();
            for (ProgramCallSite tmpCallSite : callSites.keySet()) {
                JSONObject tmpSource = new JSONObject();
                tmpSource.put("Address", tmpCallSite.getAddress());
                tmpSource.put("Function", analyzer.getFunctionById(tmpCallSite.getToFunctionId()).getFunctionName());
                tmpSources.put(tmpSource);
            }
            tmpResult.put("Sources", tmpSources);
            finalResults.put(tmpResult);
        }

        System.out.println(mayBeArguments);
        HashMap<ProgramFunction, HashSet<String>> functionUsingArguments = new HashMap<>();
        HashMap<ProgramFunction, Set<ProgramCallSite>> functionCallSites = new HashMap<>();
        for (ProgramFunction tmpFunction : allFunctions) {
            if (!tmpFunction.getFunctionName().equals("ej_get_web_page_name")) {
                continue;
            }
            System.out.println(tmpFunction.getFunctionName());
            if (maybeTargetFunctions.contains(tmpFunction)) {
                continue;
            }
            // // Tenda
            // HashMap<ProgramCallSite, String> callSites =
            // analyzer.getFunctionCallSitesUsingArgument(tmpFunction, mayBeArguments, new
            // ArrayList<>(List.of(1)), 3);
            HashMap<ProgramCallSite, Tuple<Integer, String>> callSites = analyzer
                    .getFunctionCallSitesUsingArgument(tmpFunction, mayBeArguments, null, 0);
            System.out.println(callSites.size());
            if (callSites.size() > 0) {
                HashSet<String> usingArguments = new HashSet<>();
                for (Tuple<Integer, String> tuple : callSites.values()) {
                    usingArguments.add((String) tuple.second);
                }
                functionUsingArguments.put(tmpFunction, usingArguments);
                functionCallSites.put(tmpFunction, callSites.keySet());
            }
        }

        ArrayList<ProgramFunction> possibleFunctions = new ArrayList<>();
        for (ProgramFunction tmpFunction : functionUsingArguments.keySet()) {
            // To-Do: Change this score
            int tmpScore = functionUsingArguments.get(tmpFunction).size();
            if (tmpScore >= 1) {
                JSONObject tmpResult = new JSONObject();
                if (analyzer.isMIPS()) {
                    Function tmpRawFunction = analyzer.getRawFunction(tmpFunction);

                    Register t9Register = analyzer.getProgram().getRegister("t9");
                    RegisterValue t9Value = analyzer.getProgram().getProgramContext().getRegisterValue(t9Register,
                            tmpRawFunction.getEntryPoint());
                    if (t9Value != null) {
                        tmpResult.put("t9", t9Value.getSignedValue());
                    } else {
                        tmpResult.put("t9", 0);
                    }

                    Register gpRegister = analyzer.getProgram().getRegister("gp");
                    RegisterValue gpValue = analyzer.getProgram().getProgramContext().getRegisterValue(gpRegister,
                            tmpRawFunction.getEntryPoint());
                    if (gpValue != null) {
                        tmpResult.put("gp", gpValue.getSignedValue());
                    } else {
                        tmpResult.put("gp", 0);
                    }
                }

                tmpResult.put("Address", tmpFunction.getAddress());
                tmpResult.put("Name", tmpFunction.getFunctionName());
                tmpResult.put("Judgement", "Parameters");
                tmpResult.put("Confidence", (float) tmpScore / mayBeArguments.size());

                Set<ProgramCallSite> callSites = functionCallSites.get(tmpFunction);
                JSONArray tmpSources = new JSONArray();
                for (ProgramCallSite tmpCallSite : callSites) {
                    JSONObject tmpSource = new JSONObject();
                    tmpSource.put("Address", tmpCallSite.getAddress());
                    tmpSource.put("Function",
                            analyzer.getFunctionById(tmpCallSite.getToFunctionId()).getFunctionName());
                    tmpSources.put(tmpSource);
                }
                tmpResult.put("Sources", tmpSources);
                finalResults.put(tmpResult);
            }
        }
        outputResult.put("Results", finalResults);

        // Get Relations
        List<String> fromFunctions = List.of("acosNvramConfig_set");
        List<String> toFunctions = List.of("acosNvramConfig_get");
        HashMap<String, ArrayList<ArrayList<String>>> dataFlowRelated = new HashMap<>();

        for (ProgramFunction tmpFunction : allFunctions) {
            // // Tenda
            HashMap<ProgramCallSite, Tuple<Integer, String>> callSites = analyzer
                    .getFunctionCallSitesUsingArgument(tmpFunction, mayBeArguments, null, 0);
            if (callSites.size() > 0) {
                for (Entry<ProgramCallSite, Tuple<Integer, String>> entry : callSites.entrySet()) {
                    // To-Do: judge function name and argument
                    String functionName = analyzer.getFunctionById(entry.getKey().getToFunctionId()).getFunctionName();
                    if (fromFunctions.contains(functionName)) {
                        if (!dataFlowRelated.containsKey(entry.getValue())) {
                            ArrayList<ArrayList<String>> tmpItems = new ArrayList<>();
                            tmpItems.add(new ArrayList<>());
                            tmpItems.add(new ArrayList<>());
                            dataFlowRelated.put(entry.getValue().second, tmpItems);
                        }
                        dataFlowRelated.get(entry.getValue()).get(0).add(tmpFunction.getFunctionName());
                    }

                    if (toFunctions.contains(functionName)) {
                        if (!dataFlowRelated.containsKey(entry.getValue())) {
                            ArrayList<ArrayList<String>> tmpItems = new ArrayList<>();
                            tmpItems.add(new ArrayList<>());
                            tmpItems.add(new ArrayList<>());
                            dataFlowRelated.put(entry.getValue().second, tmpItems);
                        }
                        dataFlowRelated.get(entry.getValue()).get(1).add(tmpFunction.getFunctionName());
                    }
                }
            }
        }
        outputResult.put("Related", dataFlowRelated);

        try {
            OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8");
            osw.write(outputResult.toString());
            osw.flush();
            osw.close();
        } catch (Exception ignored) {
        }
    }

    public Function getFunctionByName(String name) {
        return this.namedFunctions.get(name);
    }

    private boolean checkMaybeKeywords(String s) {
        if (s.length() < 2) {
            return false;
        }
        for (int i = 0; i < s.length(); ++i) {
            int c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '-' || c == '_' ||
                    c == '.' || c == '%')) {
                return false;
            }
        }
        return true;
    }

    private Address getAddress(ProgramAnalyzer analyzer, Varnode varnode) {
        if (varnode.isConstant()) {
            return analyzer.getProgram().getAddressFactory().getConstantAddress(varnode.getOffset());
        } else {
            return varnode.getAddress();
        }
    }

    private String getVarnodeSource(ProgramAnalyzer analyzer, Varnode node, int parameterCount) {
        ArrayList<String> sources = new ArrayList<>();

        int currentId = 0;
        LinkedList<Varnode> waitingList = new LinkedList<>();
        HashMap<Varnode, Integer> nodeIds = new HashMap<>();
        // LinkedList<Integer> ids = new LinkedList<>();
        waitingList.add(node);
        nodeIds.put(node, 0);
        // ids.add(currentId);

        ArrayList<Varnode> visited = new ArrayList<>();

        while (!waitingList.isEmpty()) {
            Varnode tmpNode = waitingList.pop();
            int tmpId = nodeIds.get(tmpNode);
            // int tmpId = ids.pop();

            visited.add(tmpNode);
            // System.out.println(tmpNode);

            if (tmpNode.isConstant()) {
                sources.add(tmpId + ": CONSTANT " + tmpNode.getOffset());
            } else {
                PcodeOp defOp = tmpNode.getDef();
                if (defOp == null) {
                    if (tmpNode.isRegister()) {
                        Register tmpRegister = analyzer.getProgram().getRegister(tmpNode);
                        if (tmpRegister != null) {
                            String registerName = tmpRegister.getName();
                            if (analyzer.extractParameterRegisters().containsKey(registerName)) {
                                int parameterIndex = analyzer.extractParameterRegisters().get(registerName);
                                if (parameterIndex < parameterCount) {
                                    sources.add(tmpId + ": PARAM " + parameterIndex);
                                }
                            }
                        }
                    } else {
                        System.out.println(tmpNode);
                    }

                } else {
                    if (defOp.getOpcode() == PcodeOp.COPY) {
                        for (Varnode n : defOp.getInputs()) {
                            if (!visited.contains(n) && !waitingList.contains(n)) {
                                waitingList.add(n);
                                nodeIds.put(n, ++currentId);
                                // ids.add(++currentId);
                            }
                        }
                    } else if (defOp.getOpcode() == PcodeOp.PTRSUB) {
                        int nodeId1 = currentId + 1;
                        int nodeId2 = currentId + 2;
                        Varnode node1 = defOp.getInput(0);
                        Varnode node2 = defOp.getInput(1);
                        if (visited.contains(node1) || waitingList.contains(node1)) {
                            nodeId1 = nodeIds.get(node1);
                        } else {
                            waitingList.add(node1);
                            nodeIds.put(node1, nodeId1);
                        }

                        if (visited.contains(node2) || waitingList.contains(node2)) {
                            nodeId2 = nodeIds.get(node2);
                        } else {
                            waitingList.add(node2);
                            nodeIds.put(node2, nodeId2);
                        }
                        sources.add(tmpId + ": SUB " + nodeId1 + " " + nodeId2);
                    } else {
                        System.out.println(defOp);
                    }
                }
            }

            // System.out.println(tmpNode.getDef());
        }
        System.out.println(sources);

        // PcodeOp defOp = node.getDef();
        // if (defOp == null) {
        //
        // } else {
        // switch (defOp.getOpcode()) {
        // case PcodeOp.COPY :
        //
        // }
        // }
        // ReferenceIterator references =
        // analyzer.getProgram().getReferenceManager().getReferencesTo(parameterAddress);
        // System.out.println("==============================");
        // while (references.hasNext()) {
        // Reference reference = references.next();
        // Address fromAddress = reference.getFromAddress();
        // System.out.println(fromAddress);
        // }
        // System.out.println("==============================");
        return "";
    }

    @Deprecated
    public void extractInputLocation(ProgramAnalyzer analyzer, ArrayList<String> keywords, String outputPath) {
        ArrayList<String> filteredFunctions = new ArrayList<>(List.of("strcmp", "strcpy", "system", "strstr",
                "memcpy", "stristr", "strncat", "fopen64", "stricmp", "atoi", "fopen", "printf", "sprintf",
                "strcasecmp",
                "strcat", "strnicmp", "snprintf", "puts", "set_mac_devName", "strncpy", "perror", "fprintf", "strncmp",
                "popen", "strcasestr", "strlcpy", "strchr", "strlen"));
        ArrayList<ProgramFunction> allFunctions = analyzer.getAllFunctions();
        HashMap<String, Integer> functionCount = new HashMap<>();
        // ArrayList<String> maybeKeywords = new ArrayList<>();
        // for (Map.Entry<String, Address>entry : this.strings.entrySet()) {
        // if (!this.checkMaybeKeywords(entry.getKey())) {
        // continue;
        // }
        // maybeKeywords.add(entry.getKey());
        // }
        ArrayList<String> maybeKeywords = keywords;

        // Get all callsites using extracted keywords
        ArrayList<ProgramFunction> maybeSourceFunctions = new ArrayList<>();
        for (ProgramFunction tmpFunction : allFunctions) {
            HashMap<ProgramCallSite, Tuple<Integer, String>> callSites = analyzer
                    .getFunctionCallSitesUsingArgument(tmpFunction, maybeKeywords);
            // possibleCallSites.put(tmpFunction.getFunctionId(), callSites);
            for (Entry<ProgramCallSite, Tuple<Integer, String>> entry : callSites.entrySet()) {
                String tmpFunctionName = entry.getKey().getToFunctionName();
                String tmpFunctionId = entry.getKey().getToFunctionId();
                ProgramFunction tmpSourceFunction = analyzer.getFunctionById(tmpFunctionId);
                if (filteredFunctions.contains(tmpFunctionName)) {
                    continue;
                }
                if (!maybeSourceFunctions.contains(tmpSourceFunction)) {
                    maybeSourceFunctions.add(tmpSourceFunction);
                }
                // if (!functionCount.containsKey(tmpFunctionName)) {
                // functionCount.put(tmpFunctionName, 1);
                // } else {
                // functionCount.put(tmpFunctionName, functionCount.get(tmpFunctionName) + 1);
                // }
            }
        }

        ArrayList<ProgramCallSite> allCallSites = new ArrayList<>();
        for (ProgramFunction tmpFunction : allFunctions) {
            ArrayList<ProgramCallSite> callSites = analyzer.getFunctionCallSites(tmpFunction, maybeSourceFunctions);
            allCallSites.addAll(callSites);
            for (ProgramCallSite programCallSite : callSites) {
                String tmpFunctionId = programCallSite.getToFunctionId();
                if (!functionCount.containsKey(tmpFunctionId)) {
                    functionCount.put(tmpFunctionId, 1);
                } else {
                    functionCount.put(tmpFunctionId, functionCount.get(tmpFunctionId) + 1);
                }
            }
        }
        // for (String maybeSourceFuncId: maybeSourceFunctionIds) {
        // analyzer.getFunctionCallSites()
        // }
        // HashMap<String, HashMap<ProgramCallSite, String>> possibleCallSites = new
        // HashMap<>();

        // analyzer.getFunctionCallSites()

        // Calculate all score of all candidates
        List<Map.Entry<String, Integer>> entryList = new ArrayList<>(functionCount.entrySet());
        entryList.sort((o1, o2) -> o2.getValue() - o1.getValue());
        int maxCount = 0;
        int minCount = 0;
        if (entryList.size() > 0) {
            maxCount = entryList.get(0).getValue();
            minCount = entryList.get(entryList.size() - 1).getValue();
        }
        // Get all source functions
        ArrayList<String> selectedSourceFunctions = new ArrayList<>();
        JSONArray sortedFunctionCount = new JSONArray();
        for (Map.Entry<String, Integer> entry : entryList) {
            float score = (((float) (entry.getValue() - minCount)) / (maxCount - minCount));
            if (score > 0.001) {
                HashMap<String, Object> tmpItem = new HashMap<>();
                selectedSourceFunctions.add(entry.getKey());
                tmpItem.put("name", entry.getKey());
                tmpItem.put("count", entry.getValue());
                tmpItem.put("score", score);
                sortedFunctionCount.put(tmpItem);
            }
        }

        HashMap<Long, HashMap<Integer, ArrayList<DDGNode>>> flows = new HashMap<>();
        HashMap<Long, HashMap<Integer, ArrayList<DDGNode>>> froms = new HashMap<>();

        HashMap<String, ArrayList<Long>> inputLocations = new HashMap<>();
        for (ProgramCallSite tmpCallSite : allCallSites) {
            String caller = tmpCallSite.getFromFunctionId();
            String callee = tmpCallSite.getToFunctionId();
            if (selectedSourceFunctions.contains(callee)) {
                if (!inputLocations.containsKey(caller)) {
                    inputLocations.put(caller, new ArrayList<>());
                }
                inputLocations.get(caller).add(tmpCallSite.getAddress());
                flows.put(tmpCallSite.getAddress(), new HashMap<>());
                froms.put(tmpCallSite.getAddress(), new HashMap<>());
            }
        }

        // Extract all features
        // Extract all froms and flows
        for (Map.Entry<String, ArrayList<Long>> entry : inputLocations.entrySet()) {
            ProgramFunction tmpPF = analyzer.getFunctionById(entry.getKey());
            ProgramDDG tmpDDG = tmpPF.getDdg();
            if (tmpDDG == null) {
                continue;
            }
            for (Map.Entry<String, ArrayList<DDGNode>> ddgNodeEntry : tmpDDG.getAllNodes().entrySet()) {
                String callingId = ddgNodeEntry.getKey();
                long callingAddress = FunctionUtils.getCallingAddress(callingId);

                ArrayList<DDGNode> ddgNodes = ddgNodeEntry.getValue();
                for (DDGNode tmpDdgNode : ddgNodes) {
                    ArrayList<DDGNode> tmpFlowNodes = tmpDdgNode.getFlows();
                    for (DDGNode tfn : tmpFlowNodes) {
                        if (entry.getValue().contains(callingAddress)) {
                            if (!flows.get(callingAddress).containsKey(tmpDdgNode.getArgumentIndex())) {
                                flows.get(callingAddress).put(tmpDdgNode.getArgumentIndex(), new ArrayList<>());
                            }
                            if (!flows.get(callingAddress).get(tmpDdgNode.getArgumentIndex()).contains(tfn)) {
                                flows.get(callingAddress).get(tmpDdgNode.getArgumentIndex()).add(tfn);
                            }
                        }
                        if (entry.getValue().contains(tfn.getInstructionAddress())) {
                            if (!froms.get(tfn.getInstructionAddress()).containsKey(tfn.getArgumentIndex())) {
                                froms.get(tfn.getInstructionAddress()).put(tfn.getArgumentIndex(), new ArrayList<>());
                            }
                            if (!froms.get(tfn.getInstructionAddress()).get(tfn.getArgumentIndex())
                                    .contains(tmpDdgNode)) {
                                froms.get(tfn.getInstructionAddress()).get(tfn.getArgumentIndex()).add(tmpDdgNode);
                            }
                        }
                    }
                }
            }
            // 这个参数在后面用到了（被其他函数调用）
            // 这个参数不是一个常量
        }

        // System.out.println(flows);

        // Extract all names and arguments
        JSONArray finalLocations = new JSONArray();
        HashMap<Long, String> nameCache = new HashMap<>();
        HashMap<Long, ArrayList<ProgramConstant>> argumentsCache = new HashMap<>();
        for (Map.Entry<String, ArrayList<Long>> entry : inputLocations.entrySet()) {
            String caller = entry.getKey();
            ProgramFunction callerFunction = analyzer.getFunctionById(caller);
            HighFunction highFunction = analyzer.decompileFunction(callerFunction);
            if (highFunction == null)
                continue;
            // Extract caller
            String callerName = callerFunction.getFunctionName();
            ArrayList<CallGraphNode> cgNodes = analyzer.getCallGraph().getCallGraphNodes(callerFunction);

            for (long calleeAddress : entry.getValue()) {
                JSONObject tmpLocation = new JSONObject();
                JSONObject locationSource = new JSONObject();
                // Extract callee and arguments
                String calleeName;
                ArrayList<ProgramConstant> arguments;
                if (!nameCache.containsKey(calleeAddress)) {
                    calleeName = this.getCalleeNameByAddress(analyzer, highFunction, calleeAddress);
                    if (calleeName.length() == 0) {
                        continue;
                    }
                    nameCache.put(calleeAddress, calleeName);
                    arguments = this.getCalleeArgumentsByAddress(analyzer, cgNodes, calleeAddress);
                    argumentsCache.put(calleeAddress, arguments);
                } else {
                    calleeName = nameCache.get(calleeAddress);
                    arguments = argumentsCache.get(calleeAddress);
                }

                tmpLocation.put("caller", callerName);
                locationSource.put("api", calleeName);
                locationSource.put("args", arguments);
                locationSource.put("address", calleeAddress);
                tmpLocation.put("source", locationSource);

                ArrayList<String> fromFunction = new ArrayList<>();
                ArrayList<Long> fromAddresses = new ArrayList<>();
                ArrayList<ArrayList<ProgramConstant>> fromArguments = new ArrayList<>();

                ArrayList<String> flowFunction = new ArrayList<>();
                ArrayList<Long> flowAddresses = new ArrayList<>();
                ArrayList<ArrayList<ProgramConstant>> flowArguments = new ArrayList<>();
                // Extract froms and flows
                for (Map.Entry<Integer, ArrayList<DDGNode>> fromNodeEntry : froms.get(calleeAddress).entrySet()) {
                    int argumentIndex = fromNodeEntry.getKey();
                    if (arguments.get(argumentIndex).maybeOutputPointer()) {
                        for (DDGNode fromNode : fromNodeEntry.getValue()) {
                            if (fromNode.getInstructionAddress() == 0) {
                                fromFunction.add("PARAMETER " + fromNode.getArgumentIndex());
                                fromAddresses.add((long) 0);
                                fromArguments.add(new ArrayList<>());
                            } else {
                                if (fromNode.getInstructionAddress() == calleeAddress)
                                    continue;
                                String fromName;
                                ArrayList<ProgramConstant> tmpFromArguments;
                                if (!nameCache.containsKey(fromNode.getInstructionAddress())) {
                                    fromName = this.getCalleeNameByAddress(analyzer, highFunction,
                                            fromNode.getInstructionAddress());
                                    nameCache.put(fromNode.getInstructionAddress(), fromName);
                                    tmpFromArguments = this.getCalleeArgumentsByAddress(analyzer,
                                            cgNodes, fromNode.getInstructionAddress());
                                    argumentsCache.put(fromNode.getInstructionAddress(), tmpFromArguments);
                                } else {
                                    fromName = nameCache.get(fromNode.getInstructionAddress());
                                    tmpFromArguments = argumentsCache.get(fromNode.getInstructionAddress());
                                }
                                fromFunction.add(fromName);
                                fromAddresses.add(fromNode.getInstructionAddress());
                                fromArguments.add(tmpFromArguments);
                            }
                        }
                    }
                }

                for (Map.Entry<Integer, ArrayList<DDGNode>> flowNodeEntry : flows.get(calleeAddress).entrySet()) {
                    int argumentIndex = flowNodeEntry.getKey();
                    if (argumentIndex == -1 || Objects.equals(arguments.get(argumentIndex), "\"\"")
                            || Objects.equals(arguments.get(argumentIndex), "[NOT DETERMINED]")) {
                        for (DDGNode flowNode : flowNodeEntry.getValue()) {
                            if (flowNode.getInstructionAddress() == 0) {
                                flowFunction.add("PARAMETER " + flowNode.getArgumentIndex());
                                flowAddresses.add((long) 0);
                                flowArguments.add(new ArrayList<>());
                            } else {
                                if (flowNode.getInstructionAddress() == calleeAddress)
                                    continue;
                                String flowName;
                                ArrayList<ProgramConstant> tmpFlowArguments;
                                if (!nameCache.containsKey(flowNode.getInstructionAddress())) {
                                    flowName = this.getCalleeNameByAddress(analyzer, highFunction,
                                            flowNode.getInstructionAddress());
                                    nameCache.put(flowNode.getInstructionAddress(), flowName);
                                    tmpFlowArguments = getCalleeArgumentsByAddress(analyzer, cgNodes,
                                            flowNode.getInstructionAddress());
                                    argumentsCache.put(flowNode.getInstructionAddress(), tmpFlowArguments);
                                } else {
                                    flowName = nameCache.get(flowNode.getInstructionAddress());
                                    tmpFlowArguments = argumentsCache.get(flowNode.getInstructionAddress());
                                }
                                flowFunction.add(flowName);
                                flowAddresses.add(flowNode.getInstructionAddress());
                                flowArguments.add(tmpFlowArguments);
                            }
                        }
                    }
                }

                JSONArray locationFrom = new JSONArray();
                for (int i = 0; i < fromFunction.size(); ++i) {
                    JSONObject locationFromItem = new JSONObject();
                    locationFromItem.put("api", fromFunction.get(i));
                    locationFromItem.put("address", fromAddresses.get(i));
                    locationFromItem.put("args", fromArguments.get(i));
                    locationFrom.put(locationFromItem);
                }

                JSONArray locationFlow = new JSONArray();
                for (int i = 0; i < flowFunction.size(); ++i) {
                    JSONObject locationFlowItem = new JSONObject();
                    locationFlowItem.put("api", flowFunction.get(i));
                    locationFlowItem.put("address", flowAddresses.get(i));
                    locationFlowItem.put("args", flowArguments.get(i));
                    locationFlow.put(locationFlowItem);
                }

                tmpLocation.put("from", locationFrom);
                tmpLocation.put("flow", locationFlow);

                finalLocations.put(tmpLocation);
            }
        }
        // for (Map.Entry<Long, ArrayList<Long>> callingAddress: froms.entrySet()) {
        // if (froms.get(callingAddress.getKey()).isEmpty() &&
        // flows.get(callingAddress.getKey()).isEmpty())
        // continue;
        // System.out.println(StringUtils.convertHexString(callingAddress.getKey(),
        // 16));
        // logArray(froms.get(callingAddress.getKey()));
        // logArray(flows.get(callingAddress.getKey()));
        // System.out.println(froms.get(callingAddress.getKey()));
        // System.out.println(flows.get(callingAddress.getKey()));
        // }

        // JSONArray locations = new JSONArray();
        // for (Map.Entry<String, HashMap<ProgramCallSite, String>> entry:
        // possibleCallSites.entrySet()) {
        // String caller = entry.getKey();
        // HashMap<ProgramCallSite, String> callSites = entry.getValue();
        // for (Map.Entry<ProgramCallSite, String> subEntry: callSites.entrySet()) {
        // if (maybeSourceFunctions.contains(subEntry.getKey().getToFunctionName())) {
        //
        // if (!inputLocations.containsKey(caller)) {
        // inputLocations.put(caller, new ArrayList<>());
        // }
        // inputLocations.get(caller).add(subEntry.getKey().getAddress());
        // HashMap<String, Object> tmpItem = new HashMap<>();
        // tmpItem.put("caller", caller);
        // tmpItem.put("callee", subEntry.getKey().getToFunctionName());
        // tmpItem.put("address", subEntry.getKey().getAddress());
        // tmpItem.put("keyword", subEntry.getValue());
        // locations.put(tmpItem);
        // }
        // }
        // }
        //
        // // Extract all features
        // for (Map.Entry<String, ArrayList<Long>> entry: inputLocations.entrySet()) {
        // if (!entry.getKey().equals("FUN_000babb8_000babb8")) {
        // continue;
        // }
        // for (long value: entry.getValue()) {
        // System.out.println(StringUtils.convertHexString(value, 16));
        // }
        //// System.out.println(entry.getKey());
        // ProgramFunction tmpPF = analyzer.getFunctionById(entry.getKey());
        // ProgramDDG tmpDDG = tmpPF.getDdg();
        // for (Map.Entry<String, ArrayList<DDGNode>> ddgNodeEntry:
        // tmpDDG.getAllNodes().entrySet()) {
        // String callingId = ddgNodeEntry.getKey();
        // System.out.println(callingId);
        // for (DDGNode ddgNode: ddgNodeEntry.getValue()) {
        // System.out.println(ddgNode.getFunctionId() + ": " +
        // ddgNode.getArgumentIndex());
        // }
        // }
        //
        //// Function callerFunction = analyzer.getRawFunction(tmpPF);
        //// HighFunction highFunction = analyzer.decompileFunction(callerFunction);
        //// Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
        //// while (ops.hasNext()) {
        //// PcodeOpAST pcodeOpAST = ops.next();
        //// if (pcodeOpAST.getOpcode() == PcodeOp.CALL || pcodeOpAST.getOpcode() ==
        // PcodeOp.CALLIND) {
        //// if
        // (!entry.getValue().contains(pcodeOpAST.getSeqnum().getTarget().getOffset()))
        // {
        //// continue;
        //// }
        //// System.out.println(pcodeOpAST.getSeqnum().getTarget());
        //// if (pcodeOpAST.getNumInputs() > 1) {
        //// Varnode[] inputs = pcodeOpAST.getInputs();
        //// for (int i = 1; i < inputs.length; ++i) {
        //// Varnode tmpInput = inputs[i];
        //// String sourceFunctionName = getVarnodeSource(analyzer, tmpInput,
        // tmpPF.getParametersCount());
        //// }
        //// System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        //// } else {
        //// }
        //// }
        //// }
        // }

        JSONObject outputResult = new JSONObject();
        outputResult.put("results", sortedFunctionCount);
        outputResult.put("locations", finalLocations);
        // outputResult.put("locations", locations);
        try {
            OutputStreamWriter osw = new OutputStreamWriter(new FileOutputStream(outputPath), "UTF-8");
            osw.write(outputResult.toString());
            osw.flush();
            osw.close();
        } catch (Exception ignored) {

        }
    }

    public void extractToDatabase(ProgramAnalyzer analyzer, ArrayList<String> keywords,
            InputStorage storage) throws SQLException {

        ArrayList<Tuple<ProgramCallSite, Integer>> selectedKeywordCallSites = extractPossibleKeywordSourceCallSites(
                analyzer);
        ArrayList<Tuple<ProgramCallSite, Integer>> selectedOSLevelCallSites = extractPossibleOSLevelSourceCallSites(
                analyzer);

        // Storage: Bin Info
        String binPath = analyzer.getProgramPath();
        Map<String, String> binInfo = parseBinInfoFromPath(binPath);
        String binHash = hashBin(binPath);

        long bin_id = storage.addBin(
                binInfo.get("vendor"), binInfo.get("firmware_id"),
                binInfo.get("path"), binHash, analyzer.getProgramBaseAddress());

        if (selectedKeywordCallSites.size() == 0 && selectedOSLevelCallSites.size() == 0) {
            return;
        }

        // Storage: Functions
        Map<ProgramFunction, Long> functionIdMap = extractFunctionInfoToDatabase(analyzer, storage, bin_id);

        // Storage: Input
        extractOSLevelInputEntriesToDatabase(analyzer, selectedOSLevelCallSites, storage, functionIdMap, bin_id);
        extractKeywordInputEntriesToDatabase(analyzer, selectedKeywordCallSites, storage, functionIdMap, bin_id);
    }

    public Map<ProgramFunction, Long> extractFunctionInfoToDatabase(ProgramAnalyzer analyzer, InputStorage storage,
            long bin_id)
            throws SQLException {
        ArrayList<ProgramFunction> allFunctions = analyzer.getAllFunctions();
        Map<ProgramFunction, Long> functionIdMap = new HashMap<>();
        for (ProgramFunction function : allFunctions) {
            // dirty code clone
            String extra_info = "";
            if (analyzer.isMIPS()) {
                Function tmpRawFunction = analyzer.getRawFunction(function);

                Register t9Register = analyzer.getProgram().getRegister("t9");
                RegisterValue t9Value = analyzer.getProgram().getProgramContext().getRegisterValue(t9Register,
                        tmpRawFunction.getEntryPoint());
                long t9 = 0;
                if (t9Value != null) {
                    t9 = t9Value.getSignedValue().longValue();
                }

                Register gpRegister = analyzer.getProgram().getRegister("gp");
                RegisterValue gpValue = analyzer.getProgram().getProgramContext().getRegisterValue(gpRegister,
                        tmpRawFunction.getEntryPoint());
                long gp = 0;
                if (gpValue != null) {
                    gp = gpValue.getSignedValue().longValue();
                }
                // create json string containt t9 and gp
                extra_info = String.format("{\"t9\": %d, \"gp\": %d}", t9, gp);
            }
            long functionId = storage.addFunc(bin_id, function.getAddress(), function.getFunctionName(), extra_info);
            functionIdMap.put(function, functionId);
        }

        // Storage: Call Graph
        ProgramCallGraph callGraph = analyzer.getCallGraph();
        for (ProgramFunction callerFunction : allFunctions) {
            ArrayList<CallGraphNode> calleeNdoes = callGraph.getCallGraphNodes(callerFunction);
            for (CallGraphNode calleeNode : calleeNdoes) {
                long caller = functionIdMap.get(callerFunction);
                ProgramFunction calleeFunction = analyzer.getProgramFunction(calleeNode.getToFunction());
                long callee = functionIdMap.get(calleeFunction);
                storage.addFuncCall(caller, callee);
            }
        }

        // Storage: Func Strings
        for (ProgramFunction callerFunction : allFunctions) {
            HashSet<Pair<String, Long>> refStrings = analyzer.getFunctionRefStrings(callerFunction);
            Long functionId = functionIdMap.get(callerFunction);
            if (functionId == null) {
                continue;
            }
            for (Pair<String, Long> refStringPair : refStrings) {
                String refString = refStringPair.first;
                Long address = refStringPair.second;
                try {
                    storage.addFuncString(functionId, address, refString);
                } catch (SQLException e) {
                    e.printStackTrace();
                    return functionIdMap;
                }
            }
        }

        return functionIdMap;
    }

    public void extractKeywordInputEntriesToDatabase(ProgramAnalyzer analyzer,
            ArrayList<Tuple<ProgramCallSite, Integer>> selectedKeywordCallSites,
            InputStorage storage, Map<ProgramFunction, Long> functionIdMap, long bin_id) throws SQLException {

        HashMap<ProgramCallSite, ArrayList<Integer>> callSiteMaybeOutArgMap = new HashMap<>();
        HashMap<ProgramCallSite, ArrayList<DataflowCallFeature>> dfCallFeatures = extractDataflowCallFeatures(analyzer,
                selectedKeywordCallSites, callSiteMaybeOutArgMap);

        for (Tuple<ProgramCallSite, Integer> callSiteTuple : selectedKeywordCallSites) {
            // Storage: Input
            ProgramCallSite callSite = callSiteTuple.first;
            int argIndex = callSiteTuple.second;

            ProgramFunction calleeFunction = analyzer.getFunctionById(callSite.getToFunctionId());
            ProgramFunction callerFunction = analyzer.getFunctionById(callSite.getFromFunctionId());

            long api_id = functionIdMap.get(calleeFunction);
            long caller_id = functionIdMap.get(analyzer.getFunctionById(callSite.getFromFunctionId()));
            Long address = callSite.getAddress();
            ArrayList<Integer> maybeOutArg = callSiteMaybeOutArgMap.get(callSite);

            JSONObject modelObject = new JSONObject();
            modelObject.put("type", "kv");
            modelObject.put("key_arg", argIndex);
            modelObject.put("out_arg", new JSONArray(maybeOutArg));
            ArrayList<CallGraphNode> cgNodes = analyzer.getCallGraph().getCallGraphNodes(callerFunction);
            ArrayList<ProgramConstant> args = this.getCalleeArgumentsByAddress(analyzer, cgNodes, address);
            String argStrings = new JSONArray(getStringList(args)).toString();
            modelObject.put("args", argStrings);
            String model = modelObject.toString();

            // TODO: 一些情况keyword可能会是null，这样就没办法search到了
            String keyword = analyzer.getConstStringArgumentAt(callSite, argIndex);
            if (keyword == null && argIndex < args.size()) {
                ProgramConstant keywordConst = args.get(argIndex);
                if (keywordConst.getType() == ProgramConstant.Type.STRING) {
                    if (checkMaybeKeywords(keywordConst.getStringValue())) {
                        keyword = keywordConst.getStringValue();
                    }
                }
            }

            long input_id = storage.addInput(bin_id, api_id, caller_id, address, keyword, model);

            // Storage: Dataflow Features
            ArrayList<DataflowCallFeature> features = dfCallFeatures.get(callSiteTuple.first);
            for (DataflowCallFeature feature : features) {
                long callee_id = functionIdMap.get(feature.getCallee());
                argStrings = new JSONArray(getStringList(feature.getCalleeArguments())).toString();
                storage.addInputDataflowCall(
                        feature.getType(), input_id, feature.getAddress(), callee_id,
                        feature.getArgumentIndex(), argStrings);
            }
        }
    }

    public void extractOSLevelInputEntriesToDatabase(ProgramAnalyzer analyzer,
            ArrayList<Tuple<ProgramCallSite, Integer>> selectedOSLevelCallSites,
            InputStorage storage, Map<ProgramFunction, Long> functionIdMap, long bin_id) throws SQLException {

        HashMap<ProgramCallSite, ArrayList<Integer>> callSiteMaybeOutArgMap = new HashMap<>();
        for (Tuple<ProgramCallSite, Integer> callSiteTuple : selectedOSLevelCallSites) {
            ArrayList<Integer> maybeOutArg = new ArrayList<>();
            maybeOutArg.add(callSiteTuple.second);
            callSiteMaybeOutArgMap.put(callSiteTuple.first, maybeOutArg);
        }
        HashMap<ProgramCallSite, ArrayList<DataflowCallFeature>> dfCallFeatures = extractDataflowCallFeatures(analyzer,
                selectedOSLevelCallSites, callSiteMaybeOutArgMap);

        for (Tuple<ProgramCallSite, Integer> callSiteTuple : selectedOSLevelCallSites) {
            // Storage: Input
            ProgramCallSite callSite = callSiteTuple.first;
            int argIndex = callSiteTuple.second;

            ProgramFunction calleeFunction = analyzer.getFunctionById(callSite.getToFunctionId());
            ProgramFunction callerFunction = analyzer.getFunctionById(callSite.getFromFunctionId());

            long api_id = functionIdMap.get(calleeFunction);
            long caller_id = functionIdMap.get(analyzer.getFunctionById(callSite.getFromFunctionId()));
            Long address = callSite.getAddress();
            ArrayList<Integer> maybeOutArg = callSiteMaybeOutArgMap.get(callSite);

            JSONObject modelObject = new JSONObject();
            modelObject.put("type", "raw");
            modelObject.put("key_arg", -1);
            modelObject.put("out_arg", new JSONArray(maybeOutArg));
            ArrayList<CallGraphNode> cgNodes = analyzer.getCallGraph().getCallGraphNodes(callerFunction);
            ArrayList<ProgramConstant> args = this.getCalleeArgumentsByAddress(analyzer, cgNodes, address);
            String argStrings = new JSONArray(getStringList(args)).toString();
            modelObject.put("args", argStrings);
            String model = modelObject.toString();

            // NO Keyword
            String keyword = "";

            long input_id = storage.addInput(bin_id, api_id, caller_id, address, keyword, model);

            // Storage: Dataflow Features
            ArrayList<DataflowCallFeature> features = dfCallFeatures.get(callSiteTuple.first);
            for (DataflowCallFeature feature : features) {
                long callee_id = functionIdMap.get(feature.getCallee());
                argStrings = new JSONArray(getStringList(feature.getCalleeArguments())).toString();
                storage.addInputDataflowCall(
                        feature.getType(), input_id, feature.getAddress(), callee_id,
                        feature.getArgumentIndex(), argStrings);
            }

            ArrayList<Pair<Long, ProgramConstant>> constants = analyzer.analyzeCallingArgumentRelatedConstants(callSite,
                    argIndex);
            for (Pair<Long, ProgramConstant> entry : constants) {
                long constRefAddress = entry.first;
                ProgramConstant constant = entry.second;
                if (constant.getType() == ProgramConstant.Type.INT)
                    storage.addInputDataflowConst(DataflowCallFeature.TYPE_FLOW, input_id, constRefAddress,
                            constant.toString());
            }

        }
    }

    /**
     * Extract dataflow features from the program, including froms and flows
     * 
     * @param analyzer
     * @param selectedCallSites
     * @return
     */
    private HashMap<ProgramCallSite, ArrayList<DataflowCallFeature>> extractDataflowCallFeatures(
            ProgramAnalyzer analyzer,
            List<Tuple<ProgramCallSite, Integer>> selectedCallSites,
            HashMap<ProgramCallSite, ArrayList<Integer>> callSiteMaybeOutArgMap) {

        HashMap<ProgramCallSite, ArrayList<DataflowCallFeature>> results = new HashMap<>();

        // address -> (argIndex -> flowNodes)
        HashMap<Long, HashMap<Integer, ArrayList<DDGNode>>> flows = new HashMap<>();

        // address -> (argIndex -> fromNodes)
        HashMap<Long, HashMap<Integer, ArrayList<DDGNode>>> froms = new HashMap<>();

        // address -> callSite
        HashMap<Long, ProgramCallSite> callSiteMap = new HashMap<>();

        // callerId -> input entry list
        HashMap<String, ArrayList<Long>> funcInputEntryAddresses = new HashMap<>();

        // Prepare data
        for (Tuple<ProgramCallSite, Integer> callSiteTuple : selectedCallSites) {
            ProgramCallSite tmpCallSite = callSiteTuple.first;
            String caller = tmpCallSite.getFromFunctionId();
            String callee = tmpCallSite.getToFunctionId();
            if (!funcInputEntryAddresses.containsKey(caller)) {
                funcInputEntryAddresses.put(caller, new ArrayList<>());
            }
            results.put(tmpCallSite, new ArrayList<>());
            funcInputEntryAddresses.get(caller).add(tmpCallSite.getAddress());
            flows.put(tmpCallSite.getAddress(), new HashMap<>());
            froms.put(tmpCallSite.getAddress(), new HashMap<>());
            callSiteMap.put(tmpCallSite.getAddress(), tmpCallSite);
        }

        // Analyze flows and froms
        for (Map.Entry<String, ArrayList<Long>> entry : funcInputEntryAddresses.entrySet()) {
            ProgramFunction tmpPF = analyzer.getFunctionById(entry.getKey());
            ProgramDDG tmpDDG = tmpPF.getDdg();
            if (tmpDDG == null) {
                continue;
            }
            for (Map.Entry<String, ArrayList<DDGNode>> ddgNodeEntry : tmpDDG.getAllNodes().entrySet()) {
                String callingId = ddgNodeEntry.getKey();
                long callingAddress = FunctionUtils.getCallingAddress(callingId);

                boolean isFlow = entry.getValue().contains(callingAddress);

                ArrayList<DDGNode> ddgNodes = ddgNodeEntry.getValue();
                for (DDGNode tmpDdgNode : ddgNodes) {
                    ArrayList<DDGNode> tmpFlowNodes = tmpDdgNode.getFlows();
                    for (DDGNode tfn : tmpFlowNodes) {
                        if (isFlow) {
                            if (tfn.getFunctionId() == null || !(tfn.getFunctionId().equals(tmpDdgNode.getFunctionId())
                                    && tfn.getArgumentIndex() == tmpDdgNode.getArgumentIndex())) {
                                if (!flows.get(callingAddress).containsKey(tmpDdgNode.getArgumentIndex())) {
                                    flows.get(callingAddress).put(tmpDdgNode.getArgumentIndex(), new ArrayList<>());
                                }
                                if (!flows.get(callingAddress).get(tmpDdgNode.getArgumentIndex()).contains(tfn)) {
                                    flows.get(callingAddress).get(tmpDdgNode.getArgumentIndex()).add(tfn);
                                }
                            }
                        }
                        if (entry.getValue().contains(tfn.getInstructionAddress())) {
                            if (tfn.getFunctionId() == null || !(tfn.getFunctionId().equals(tmpDdgNode.getFunctionId())
                                    && tfn.getArgumentIndex() == tmpDdgNode.getArgumentIndex())) {
                                if (!froms.get(tfn.getInstructionAddress()).containsKey(tfn.getArgumentIndex())) {
                                    froms.get(tfn.getInstructionAddress()).put(tfn.getArgumentIndex(),
                                            new ArrayList<>());
                                }
                                if (!froms.get(tfn.getInstructionAddress()).get(tfn.getArgumentIndex())
                                        .contains(tmpDdgNode)) {
                                    froms.get(tfn.getInstructionAddress()).get(tfn.getArgumentIndex()).add(tmpDdgNode);
                                }
                            }
                        }
                    }
                }
            }
            // 这个参数在后面用到了（被其他函数调用）
            // 这个参数不是一个常量
        }

        // Extract features
        HashMap<Long, String> nameCache = new HashMap<>();
        HashMap<Long, ArrayList<ProgramConstant>> argumentsCache = new HashMap<>();
        for (Map.Entry<String, ArrayList<Long>> entry : funcInputEntryAddresses.entrySet()) { // For each caller
            String caller = entry.getKey();
            ProgramFunction callerFunction = analyzer.getFunctionById(caller);
            HighFunction highFunction = analyzer.decompileFunction(callerFunction);
            if (highFunction == null)
                continue;

            // Extract caller
            ArrayList<CallGraphNode> cgNodes = analyzer.getCallGraph().getCallGraphNodes(callerFunction);

            for (long calleeAddress : entry.getValue()) { // For each input entry

                ProgramCallSite inputCallSite = callSiteMap.get(calleeAddress);
                List<DataflowCallFeature> dataflowCallFeatures = results.get(inputCallSite);
                assert null != dataflowCallFeatures;

                // Extract callee and arguments
                String calleeName;
                ArrayList<ProgramConstant> arguments;
                if (!nameCache.containsKey(calleeAddress)) {
                    calleeName = this.getCalleeNameByAddress(analyzer, highFunction, calleeAddress);
                    if (calleeName.length() == 0) {
                        continue;
                    }
                    nameCache.put(calleeAddress, calleeName);
                    arguments = this.getCalleeArgumentsByAddress(analyzer, cgNodes, calleeAddress);
                    argumentsCache.put(calleeAddress, arguments);
                } else {
                    calleeName = nameCache.get(calleeAddress);
                    arguments = argumentsCache.get(calleeAddress);
                }

                ArrayList<Integer> maybeArgumentIndex;
                boolean knownOutArg = callSiteMaybeOutArgMap.containsKey(inputCallSite);
                if (knownOutArg) {
                    maybeArgumentIndex = callSiteMaybeOutArgMap.get(inputCallSite);
                } else {
                    maybeArgumentIndex = new ArrayList<>();
                    callSiteMaybeOutArgMap.put(inputCallSite, maybeArgumentIndex);
                }
                // Extract features of froms
                for (Map.Entry<Integer, ArrayList<DDGNode>> fromNodeEntry : froms.get(calleeAddress).entrySet()) {
                    int argumentIndex = fromNodeEntry.getKey();
                    if (argumentIndex >= arguments.size() || argumentIndex < 0)
                        continue;
                    if (arguments.get(argumentIndex).maybeOutputPointer()) {
                        for (DDGNode fromNode : fromNodeEntry.getValue()) {
                            if (fromNode.getInstructionAddress() != 0) {
                                if (fromNode.getInstructionAddress() == calleeAddress)
                                    continue;
                                String fromName;
                                ArrayList<ProgramConstant> tmpFromArguments;
                                if (!nameCache.containsKey(fromNode.getInstructionAddress())) {
                                    fromName = this.getCalleeNameByAddress(analyzer, highFunction,
                                            fromNode.getInstructionAddress());
                                    nameCache.put(fromNode.getInstructionAddress(), fromName);
                                    tmpFromArguments = this.getCalleeArgumentsByAddress(analyzer, cgNodes,
                                            fromNode.getInstructionAddress());
                                    argumentsCache.put(fromNode.getInstructionAddress(), tmpFromArguments);
                                } else {
                                    fromName = nameCache.get(fromNode.getInstructionAddress());
                                    tmpFromArguments = argumentsCache.get(fromNode.getInstructionAddress());
                                }
                                ProgramFunction callee = this.getCalleeFunctionByAddress(analyzer, highFunction,
                                        fromNode.getInstructionAddress());
                                assert null != callee;
                                if (null == callee)
                                    continue;
                                DataflowCallFeature dataflowCallFeature = new DataflowCallFeature("from",
                                        fromNode.getInstructionAddress(), callee, argumentIndex, tmpFromArguments);
                                dataflowCallFeatures.add(dataflowCallFeature);
                            }
                        }
                    }
                }

                // Extract features of flows

                for (Map.Entry<Integer, ArrayList<DDGNode>> flowNodeEntry : flows.get(calleeAddress).entrySet()) {
                    int argumentIndex = flowNodeEntry.getKey();
                    if (argumentIndex >= arguments.size())
                        continue;
                    ProgramConstant argument = ProgramConstant.Unknown;
                    if (argumentIndex != -1)
                        argument = arguments.get(argumentIndex);

                    if (knownOutArg && !maybeArgumentIndex.contains(argumentIndex))
                        continue;
                    else if (!knownOutArg && !argument.maybeOutputPointer())
                        continue;
                    maybeArgumentIndex.add(argumentIndex);

                    for (DDGNode flowNode : flowNodeEntry.getValue()) {
                        if (flowNode.getInstructionAddress() != 0) {
                            // The argument is overwritten by another source function
                            if (flowNode.getInstructionAddress() == calleeAddress)
                                continue;
                            String flowName;
                            ArrayList<ProgramConstant> tmpFlowArguments;
                            if (!nameCache.containsKey(flowNode.getInstructionAddress())) {
                                flowName = this.getCalleeNameByAddress(analyzer, highFunction,
                                        flowNode.getInstructionAddress());
                                nameCache.put(flowNode.getInstructionAddress(), flowName);
                                tmpFlowArguments = getCalleeArgumentsByAddress(analyzer, cgNodes,
                                        flowNode.getInstructionAddress());
                                argumentsCache.put(flowNode.getInstructionAddress(), tmpFlowArguments);
                            } else {
                                flowName = nameCache.get(flowNode.getInstructionAddress());
                                tmpFlowArguments = argumentsCache.get(flowNode.getInstructionAddress());
                            }
                            ProgramFunction callee = this.getCalleeFunctionByAddress(analyzer, highFunction,
                                    flowNode.getInstructionAddress());
                            assert null != callee;
                            if (null == callee)
                                continue;
                            DataflowCallFeature dataflowCallFeature = new DataflowCallFeature("flow",
                                    flowNode.getInstructionAddress(), callee, argumentIndex, tmpFlowArguments);
                            dataflowCallFeatures.add(dataflowCallFeature);
                        }
                    }

                }

                // output maybeArgument Index
                callSiteMaybeOutArgMap.put(inputCallSite, maybeArgumentIndex);
            }
        }
        return results;
    }

    /**
     * Extract possible source call sites
     * 
     * @param analyzer
     * @return Callsites and their keyword argument indexes
     */
    private ArrayList<Tuple<ProgramCallSite, Integer>> extractPossibleKeywordSourceCallSites(ProgramAnalyzer analyzer) {

        ArrayList<String> filteredFunctions = new ArrayList<>(List.of("strcpy", "system",
                "memcpy", "strncat", "fopen64", "atoi", "fopen", "printf", "sprintf",
                "strcat", "snprintf", "puts", "set_mac_devName", "strncpy", "perror", "fprintf",
                "popen", "strlcpy", "strchr", "strlen", "strcmp", "stricmp", "strnicmp", "strncmp"));
        ArrayList<String> generalFunctions = new ArrayList<>(List.of("strstr",
                "stristr", "strcasecmp", "strcasestr"));
        HashMap<String, Integer> functionCount = new HashMap<>();
        HashMap<String, Integer> functionDeCount = new HashMap<>();
        Set<String> maybeKeywords = new HashSet<>();
        for (Map.Entry<String, Address> entry : this.strings.entrySet()) {
            if (!this.checkMaybeKeywords(entry.getKey())) {
                continue;
            }
            maybeKeywords.add(entry.getKey());
        }

        ArrayList<ProgramFunction> allFunctions = analyzer.getAllFunctions();

        // Get all possible source callsites using extracted keywords
        ArrayList<ProgramCallSite> allCallSites = new ArrayList<>();

        Map<ProgramFunction, Integer> functionKeywordArgIdxMap = new HashMap<>();
        Map<ProgramCallSite, Integer> callSiteKeywordArgIdxMap = new HashMap<>();

        ArrayList<ProgramFunction> maybeSourceFunctions = new ArrayList<>();
        for (ProgramFunction tmpFunction : allFunctions) {
            HashMap<ProgramCallSite, Tuple<Integer, String>> callSitesKeywordMap = analyzer
                    .getFunctionCallSitesUsingArgument(tmpFunction, maybeKeywords);
            for (ProgramCallSite callSite : callSitesKeywordMap.keySet()) {
                Tuple<Integer, String> argTuple = callSitesKeywordMap.get(callSite);
                int argIndex = argTuple.first;
                String tmpFunctionName = callSite.getToFunctionName();
                String tmpFunctionId = callSite.getToFunctionId();
                ProgramFunction tmpSourceFunction = analyzer.getFunctionById(tmpFunctionId);
                if (filteredFunctions.contains(tmpFunctionName)) {
                    continue;
                }
                if (generalFunctions.contains(tmpFunctionName)) {
                    // Don't generally treat these functions as source functions
                    allCallSites.add(callSite);
                    callSiteKeywordArgIdxMap.put(callSite, argIndex);
                    continue;
                }
                if (!maybeSourceFunctions.contains(tmpSourceFunction)) {
                    maybeSourceFunctions.add(tmpSourceFunction);
                    functionKeywordArgIdxMap.put(tmpSourceFunction, argIndex);
                }
            }
        }

        // Extend the source callsites
        for (ProgramFunction tmpFunction : allFunctions) {
            ArrayList<ProgramCallSite> callSites = analyzer.getFunctionCallSites(tmpFunction, maybeSourceFunctions);

            for (ProgramCallSite programCallSite : callSites) {
                Integer argIndex = functionKeywordArgIdxMap
                        .get(analyzer.getFunctionById(programCallSite.getToFunctionId()));

                String tmpFunctionId = programCallSite.getToFunctionId();
                // leverage inferred argument index to deprioritize false positives
                String constParameter = analyzer.getConstStringArgumentAt(programCallSite, argIndex);

                if (!functionDeCount.containsKey(tmpFunctionId)) {
                    functionDeCount.put(tmpFunctionId, 0);
                }

                if (null != constParameter && !checkMaybeKeywords(constParameter)) {
                    // Argument is a constant string, but not a keyword
                    functionDeCount.put(tmpFunctionId, functionDeCount.get(tmpFunctionId) + 1);
                    continue;
                }

                allCallSites.add(programCallSite);
                callSiteKeywordArgIdxMap.put(programCallSite, argIndex);

                if (null == constParameter) {
                    functionDeCount.put(tmpFunctionId, functionDeCount.get(tmpFunctionId) + 1);
                    continue;
                }

                if (!functionCount.containsKey(tmpFunctionId)) {
                    functionCount.put(tmpFunctionId, 1);
                } else {
                    functionCount.put(tmpFunctionId, functionCount.get(tmpFunctionId) + 1);
                }
            }
        }

        // Calculate all score of all candidates
        List<Map.Entry<String, Integer>> entryList = new ArrayList<>(functionCount.entrySet());
        entryList.sort((o1, o2) -> o2.getValue() - o1.getValue());
        int maxCount = 0;
        int minCount = 0;
        if (entryList.size() > 0) {
            maxCount = entryList.get(0).getValue();
            minCount = entryList.get(entryList.size() - 1).getValue();
        }

        // Get all source functions
        ArrayList<String> selectedSourceFunctions = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : entryList) {
            float score = (((float) (entry.getValue() - minCount)) / (maxCount - minCount));
            if (score > 0.001) {
                selectedSourceFunctions.add(entry.getKey());
            }
        }

        // By portion
        for (Map.Entry<String, Integer> entry : functionCount.entrySet()) {
            int count = entry.getValue();
            int deCount = functionDeCount.get(entry.getKey());
            float score = (float) count / (count + deCount);
            if (score > 0.5) {
                selectedSourceFunctions.add(entry.getKey());
            }
        }

        // Select callSites
        ArrayList<Tuple<ProgramCallSite, Integer>> selectedCallSites = new ArrayList<>();
        for (ProgramCallSite tmpCallSite : allCallSites) {
            String calleeFunctionId = tmpCallSite.getToFunctionId();
            if (selectedSourceFunctions.contains(calleeFunctionId)) {
                Integer argIndex = callSiteKeywordArgIdxMap.get(tmpCallSite);
                selectedCallSites.add(new Tuple<ProgramCallSite, Integer>(tmpCallSite, argIndex));
            }
        }

        return selectedCallSites;
    }

    private ArrayList<Tuple<ProgramCallSite, Integer>> extractPossibleOSLevelSourceCallSites(ProgramAnalyzer analyzer) {
        List<String> OSFuncNames = List.of("read", "recv", "recvfrom");
        int argIndex = 1;

        ArrayList<ProgramFunction> sourceFunctions = new ArrayList<>();
        for (String funcName : OSFuncNames) {
            ArrayList<ProgramFunction> tmpSourceFunctions = analyzer.getFunctionsByName(funcName, false);
            sourceFunctions.addAll(tmpSourceFunctions);
        }

        ArrayList<ProgramFunction> allFunctions = analyzer.getAllFunctions();

        // Get all callsites
        ArrayList<ProgramCallSite> allCallSites = new ArrayList<>();
        for (ProgramFunction tmpFunction : allFunctions) {
            ArrayList<ProgramCallSite> tmpCallSites = analyzer.getFunctionCallSites(tmpFunction, sourceFunctions);

            // Exclude call to wrapper
            for (ProgramCallSite tmpCallSite : tmpCallSites) {
                String tmpCallerName = tmpCallSite.getFromFunctionName();
                if (OSFuncNames.contains(tmpCallerName)) {
                    continue;
                }
                allCallSites.add(tmpCallSite);
            }
        }

        // Select callSites
        ArrayList<Tuple<ProgramCallSite, Integer>> selectedCallSites = new ArrayList<>();
        for (ProgramCallSite tmpCallSite : allCallSites) {
            Integer tmpArgIndex = argIndex;
            ProgramConstant objConst = analyzer.getArgumentConstant(tmpCallSite, 0);
            // Skip read(0, buf, XX)
            if (!objConst.maybeOutputPointer()) {
                continue;
            }
            selectedCallSites.add(new Tuple<ProgramCallSite, Integer>(tmpCallSite, tmpArgIndex));
        }

        return selectedCallSites;
    }

    private Map<String, String> parseBinInfoFromPath(String binPath) {
        Map<String, String> result = new HashMap<>();
        String[] pathItems = binPath.split("/");
        int unpackedIndex = 0;
        for (; unpackedIndex < pathItems.length; ++unpackedIndex) {
            if (pathItems[unpackedIndex].equals("unpacked"))
                break;
        }
        // unknown path format, I suggest not handle this case
        if (unpackedIndex == pathItems.length) {
            return null;
        }

        String vendor = pathItems[unpackedIndex + 1];
        String firmware_id = pathItems[unpackedIndex + 2];
        String path = String.join("/", Arrays.copyOfRange(pathItems, unpackedIndex + 3, pathItems.length));
        result.put("vendor", vendor);
        result.put("firmware_id", firmware_id);
        result.put("path", path);
        return result;
    }

    private String hashBin(String bin_path) {
        // hash the target binary with sha256, and return hex string
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(Files.readAllBytes(Paths.get(bin_path)));
            // convert hash to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private String getCalleeNameByAddress(ProgramAnalyzer analyzer, HighFunction highFunction, long address) {
        ProgramFunction calleeFunction = getCalleeFunctionByAddress(analyzer, highFunction, address);
        if (calleeFunction == null) {
            return "";
        }
        return calleeFunction.getFunctionName();
    }

    private ProgramFunction getCalleeFunctionByAddress(ProgramAnalyzer analyzer, HighFunction highFunction,
            long address) {
        Iterator<PcodeOpAST> pcodeOps = highFunction.getPcodeOps(analyzer.getFlatProgramAPI().toAddr(address));
        while (pcodeOps.hasNext()) {
            PcodeOpAST pcodeOpAST = pcodeOps.next();
            if (pcodeOpAST.getOpcode() == PcodeOp.CALL || pcodeOpAST.getOpcode() == PcodeOp.CALLIND) {
                Address calleeAddress = pcodeOpAST.getInput(0).getAddress();
                ProgramFunction calleeFunction = analyzer.getFunctionByAddress(calleeAddress.getOffset());
                if (calleeFunction == null) {
                    continue;
                }
                return calleeFunction;
            }
        }
        return null;
    }

    private ArrayList<ProgramConstant> getCalleeArgumentsByAddress(ProgramAnalyzer analyzer,
            ArrayList<CallGraphNode> cgNodes, long address) {
        ArrayList<ProgramConstant> results = new ArrayList<>();
        for (CallGraphNode cgNode : cgNodes) {
            String callerFunctionId = FunctionUtils.getFunctionID(cgNode.getFromFunction());

            if (cgNode.getCallerAddress().getOffset() == address) {
                int argumentCount = cgNode.getArgumentsCount();
                for (int i = 0; i < argumentCount; ++i) {
                    CallArgument tmpArgument = cgNode.getArgument(i);
                    ProgramConstant constant = analyzer.getArgumentConstant(callerFunctionId, tmpArgument);
                    results.add(constant);
                }
            }

        }
        return results;
    }

    private ArrayList<String> getStringList(ArrayList<ProgramConstant> constants) {
        ArrayList<String> results = new ArrayList<>();
        for (ProgramConstant constant : constants) {
            results.add(constant.toString());
        }
        return results;
    }

    private void logArray(ArrayList<Long> list) {
        for (long l : list) {
            System.out.print(StringUtils.convertHexString(l, 16) + ", ");
        }
        System.out.println("");
    }

}

class DataflowCallFeature {
    private long address;
    private ProgramFunction callee;
    private int argumentIndex;
    private ArrayList<ProgramConstant> calleeArguments;
    private String type;

    public static String TYPE_FROM = "from";
    public static String TYPE_FLOW = "flow";

    public DataflowCallFeature(String type, long address, ProgramFunction callee, int argumentIndex,
            ArrayList<ProgramConstant> calleeArguments) {
        this.address = address;
        this.callee = callee;
        this.argumentIndex = argumentIndex;
        this.calleeArguments = calleeArguments;
        if (!type.equals(TYPE_FROM) && !type.equals(TYPE_FLOW)) {
            throw new IllegalArgumentException("type must be from or flow");
        }
        this.type = type;
    }

    public int getArgumentIndex() {
        return argumentIndex;
    }

    public String getType() {
        return type;
    }

    public long getAddress() {
        return address;
    }

    public ProgramFunction getCallee() {
        return callee;
    }

    public ArrayList<ProgramConstant> getCalleeArguments() {
        return calleeArguments;
    }
}
