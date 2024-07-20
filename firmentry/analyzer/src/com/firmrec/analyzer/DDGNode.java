package com.firmrec.analyzer;

import com.firmrec.utils.StringUtils;

import java.util.ArrayList;

public class DDGNode {
    private long instructionAddress;
    private String functionId;
    private int argumentIndex;
    private ArrayList<DDGNode> flows;

    public DDGNode(long instructionAddress, String functionId, int argumentIndex) {
        this.instructionAddress = instructionAddress;
        this.functionId = functionId;
        this.argumentIndex = argumentIndex;
        this.flows = new ArrayList<>();
    }

    public long getInstructionAddress() {
        return this.instructionAddress;
    }

    public String getFunctionId() {

        return this.functionId;
    }

    public int getArgumentIndex() {
        return this.argumentIndex;
    }

    public ArrayList<DDGNode> getFlows() {
        return this.flows;
    }

    public void addFlowTo(DDGNode node) {
        for (int i = 0; i < this.flows.size(); ++i) {
            // Heuristic: Order flow by address
            if (node.getInstructionAddress() < this.flows.get(i).getInstructionAddress()) {
                this.flows.add(i, node);
                return;
            }
        }
        this.flows.add(node);
    }

    @Override
    public String toString() {
        StringBuilder description = new StringBuilder();
        description.append(StringUtils.convertHexString(this.instructionAddress, 16)).append(": ")
                .append(this.functionId);
        description.append(" (").append(this.argumentIndex).append(")");
        return description.toString();
    }
}
