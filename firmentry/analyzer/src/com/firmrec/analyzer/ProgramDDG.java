package com.firmrec.analyzer;

import com.firmrec.model.ProgramFunction;

import java.util.ArrayList;
import java.util.HashMap;


/**
 * The Data Dependency Graph of each function in program
 * */
public class ProgramDDG {

    private ProgramFunction function;
    private HashMap<String, ArrayList<DDGNode>> nodes;
    public ProgramDDG(ProgramFunction function) {
        this.function = function;
        this.nodes = new HashMap<>();

        this.nodes.put("0x0", new ArrayList<>());

        for (int i = 0; i < this.function.getParametersCount(); ++i) {
            DDGNode tmpNode = new DDGNode(0, function.getFunctionId(), i);
            this.nodes.get("0x0").add(tmpNode);
        }
    }

    public void addNode(long address, String functionId, DDGNode node) {
        String callingId = FunctionUtils.getCallingId(address, functionId);
        if (!this.nodes.containsKey(callingId)) {
            this.nodes.put(callingId, new ArrayList<>());
        }
        this.nodes.get(callingId).add(node);
    }

    public DDGNode getNode(String callingId, int index) {
        if (!this.nodes.containsKey(callingId)) {
            return null;
        }
        ArrayList<DDGNode> allNodes = this.nodes.get(callingId);
        for (DDGNode tmpNode: allNodes) {
            if (tmpNode.getArgumentIndex() == index) {
                return tmpNode;
            }
        }
        return null;
    }

    public HashMap<String, ArrayList<DDGNode>> getAllNodes() {
        return this.nodes;
    }
}
