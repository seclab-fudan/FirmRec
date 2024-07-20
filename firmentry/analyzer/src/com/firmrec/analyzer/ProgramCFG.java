package com.firmrec.analyzer;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;

import java.util.*;


/**
 * The Control Flow Graph of each function in program
 * */
public class ProgramCFG {
    private Function function;
    private Long entryAddress;
    private FlatProgramAPI flatProgramAPI;
    private HashMap<String, CFGNode> instructionFlows;
    private HashMap<String, CFGBasicBlock> basicBlocks;
    public ProgramCFG(FlatProgramAPI flatProgramAPI, Function function) {
        this.function = function;
        this.flatProgramAPI = flatProgramAPI;
        this.instructionFlows = new HashMap<>();
        this.basicBlocks = new HashMap<>();

        this.entryAddress = this.function.getEntryPoint().getOffset();

        Set<Address> visited = new HashSet<>();
        LinkedList<Address> workList = new LinkedList<>();
        workList.add(this.flatProgramAPI.toAddr(this.entryAddress));

        ArrayList<Address> blockAddresses = new ArrayList<>();
        blockAddresses.add(this.flatProgramAPI.toAddr(this.entryAddress));

        visited = new HashSet<>();
        workList.add(this.flatProgramAPI.toAddr(this.entryAddress));
        while (!workList.isEmpty()) {
            Address current = workList.remove();
            if (visited.contains(current)) {
                continue;
            }
            visited.add(current);

            Instruction currentInst = this.flatProgramAPI.getInstructionAt(current);
//            System.out.println(currentInst);
            if (currentInst == null) {
                continue;
            }

            /* Add node */
            CFGNode currentNode = new CFGNode(currentInst, current);
            this.instructionFlows.put(current.toString(), currentNode);

            FlowType flowType = currentInst.getFlowType();
//            System.out.println(flowType.isFallthrough());
//            System.out.println(flowType.isConditional());
//            System.out.println(flowType.isCall());
//            System.out.println(flowType.isTerminal());
//            System.out.println(workList.isEmpty());
            if (flowType.isFallthrough() || flowType.isConditional() || flowType.isCall()) {
                Address flowAddress = currentInst.getFallThrough();
                if (flowAddress == null) {
                    continue;
                }
                Instruction tmpInstruction = this.flatProgramAPI.getInstructionAt(flowAddress);
                if (tmpInstruction == null) {
                    continue;
                }
                workList.add(flowAddress);
                currentNode.addFlowTo(flowAddress);
            }

            if (flowType.isTerminal()) {
                // To-Do: There exists some `b 0xXXXXX` instructions
                //   not consider it now
                continue;
            }

            if (flowType.isJump()) {
                Address[] flows = currentInst.getFlows();
                if (flows.length == 0) continue;

                if (flowType.isConditional() || flowType.isUnConditional()) {
                    Address tmpAddress = flows[0];
                    Instruction tmpInstruction = this.flatProgramAPI.getInstructionAt(tmpAddress);
                    if (tmpInstruction == null) {
                        continue;
                    }
                    workList.add(tmpAddress);
                    currentNode.addFlowTo(tmpAddress);
                    if (!blockAddresses.contains(tmpAddress)) {
                        blockAddresses.add(tmpAddress);
                    }
                } else {
                    // May have more than one flows
                    for (Address tmpAddress : flows) {
                        Instruction tmpInstruction = this.flatProgramAPI.getInstructionAt(tmpAddress);
                        if (tmpInstruction == null) {
                            continue;
                        }
                        workList.add(tmpAddress);
                        currentNode.addFlowTo(tmpAddress);
                        if (!blockAddresses.contains(tmpAddress)) {
                            blockAddresses.add(tmpAddress);
                        }
                    }
                }

                if (currentInst.getFallThrough() != null) {
                    if (!blockAddresses.contains(currentInst.getFallThrough())) {
                        blockAddresses.add(currentInst.getFallThrough());
                    }
                }
            }
        }
//        System.out.println("Finish ProgramCFG construct");
        
    }

    public ArrayList<ArrayList<String>> getFunctionFlows() {
        ArrayList<ArrayList<String>> results = new ArrayList<>();

        LinkedList<Address> workStack = new LinkedList<>();
        workStack.push(this.flatProgramAPI.toAddr(this.entryAddress));

        LinkedList<ArrayList<String>> flowStack = new LinkedList<>();
        flowStack.push(new ArrayList<>());

        HashMap<String, Integer> visitedAddress = new HashMap<>();

        while (!workStack.isEmpty()) {
            Address currentAddress = workStack.pop();
//            System.out.println(currentAddress);
            ArrayList<String> currentFlow = flowStack.pop();

            String addressString = currentAddress.toString();

            CFGNode currentNode = this.instructionFlows.get(addressString);
            if (currentNode == null) {
                continue;
            }

            Instruction currentInst = currentNode.getFromInstruction();
            FlowType flowType = currentInst.getFlowType();
            if (flowType.isCall()) {
                Address[] addresses = currentInst.getFlows();
                if (addresses.length != 0) {
                    Address callingAddress = addresses[0];
                    Function callingFunc = this.flatProgramAPI.getFunctionAt(callingAddress);
                    if (callingFunc != null) {
                        currentFlow.add(FunctionUtils.getFunctionID(callingFunc));
                    }
                }
            }
//            System.out.println(currentNode.getToAddresses());
            if (currentNode.getToAddresses().size() == 0) {
                ArrayList<String> tmpFlows = (ArrayList<String>) currentFlow.clone();
                if (!results.contains(tmpFlows)) {
                    results.add(tmpFlows);
                }
            } else {
                if (currentNode.getToAddresses().size() > 1) {
                    for (Address toAddress : currentNode.getToAddresses()) {
                        String toAddressString = toAddress.toString();
                        String addressKey = addressString + toAddressString;
                        if (visitedAddress.containsKey(addressKey) && visitedAddress.get(addressKey) > 1) {
                            continue;
                        }
                        if (!visitedAddress.containsKey(addressKey)) {
                            visitedAddress.put(addressKey, 0);
                        }
                        visitedAddress.put(addressKey, visitedAddress.get(addressKey) + 1);
                        workStack.push(toAddress);
                        flowStack.push((ArrayList<String>) currentFlow.clone());
                    }
                } else {
                    Address toAddress = currentNode.getToAddresses().get(0);
                    String toAddressString = toAddress.toString();
                    String addressKey = addressString + toAddressString;
                    if (visitedAddress.containsKey(addressKey) && visitedAddress.get(addressKey) > 1) {
                        continue;
                    }
                    if (!visitedAddress.containsKey(addressKey)) {
                        visitedAddress.put(addressKey, 0);
                    }
                    visitedAddress.put(addressKey, visitedAddress.get(addressKey) + 1);
                    workStack.push(toAddress);
                    flowStack.push((ArrayList<String>) currentFlow.clone());
                }
            }

        }
        return results;
    }

    public ArrayList<ArrayList<CFGNode>> getBasicBlocks() {
        ArrayList<ArrayList<CFGNode>> results = new ArrayList<>();

        LinkedList<Address> workStack = new LinkedList<>();
        workStack.push(this.flatProgramAPI.toAddr(this.entryAddress));

        ArrayList<CFGNode> tmpBlocks = null;
        for (Map.Entry<String, CFGNode> entry: this.instructionFlows.entrySet()) {
            if (entry.getValue().getFromInstruction().getFlowType().isCall()) {
                System.out.println("CYLIN!!!!!!!!!!!!!!!!");
                System.out.println(entry.getValue().getToAddresses());
                System.out.println("CYLIN!!!!!!!!!!!!!!!!");
            }
//            System.out.println(entry.getValue().getFromInstruction().getFlowType());
        }
//        while (!workStack.isEmpty()) {
//            Address currentAddress = workStack.pop();
//            String addressString = currentAddress.toString();
//            CFGNode currentNode = this.instructionFlows.get(addressString);
//            if (currentNode == null) {
//                continue;
//            }
//
//            tmpBlocks = new ArrayList<>();
//            tmpBlocks.add(currentNode);
//            while (true) {
//                if (currentNode.getToAddresses().size() == 0) {
//                    break;
//                } else {
//                    if (currentNode.getFromInstruction().getFlowType().isCall()) {
//                        System.out.println("CYLIN!!!!!!");
//                        System.out.println(currentNode.getToAddresses());
//                        break;
//                    } else {
//                        break;
//                    }
//                }
//                if (currentNode.getToAddresses().size() == 1) {
//                    currentAddress = currentNode.getToAddresses().get(0);
//                    addressString = currentAddress.toString();
//                    currentNode = this.instructionFlows.get(addressString);
//                    if (currentNode == null) {
//                        break;
//                    }
//                }
//            }

//        }

        return results;
    }
}
