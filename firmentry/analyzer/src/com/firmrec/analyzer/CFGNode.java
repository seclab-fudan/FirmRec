package com.firmrec.analyzer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

import java.util.ArrayList;

public class CFGNode {
    private Instruction fromInstruction;
    private Address fromAddress;
    private ArrayList<Address> toAddresses;

    public CFGNode(Instruction fromInstruction, Address fromAddress) {
        this.fromInstruction = fromInstruction;
        this.fromAddress = fromAddress;
        this.toAddresses = new ArrayList<>();
    }

    public void addFlowTo(Address toAddress) {
        if (!this.toAddresses.contains(toAddress)) {
            this.toAddresses.add(toAddress);
        }
    }

    public Instruction getFromInstruction() {
        return this.fromInstruction;
    }

    public Address getFromAddress() {
        return this.fromAddress;
    }

    public ArrayList<Address> getToAddresses() {
        return this.toAddresses;
    }

}
