package com.firmrec.analyzer;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

import java.util.ArrayList;

public class CFGBasicBlock {
    private Address entryAddress;
    private ArrayList<Address> blockAddresses;
    private ArrayList<Instruction> blockInstructions;
    private ArrayList<String> flowsTo;

    public CFGBasicBlock(Address entryAddress) {
        this.entryAddress = entryAddress;
        this.blockAddresses = new ArrayList<>();
        this.blockInstructions = new ArrayList<>();
        this.flowsTo = new ArrayList<>();
    }

    public Address getEntryAddress() {
        return this.entryAddress;
    }

    public void add(Address address, Instruction instruction) {
        this.blockAddresses.add(address);
        this.blockInstructions.add(instruction);
    }

    public void flowTo(String key) {
        if (this.flowsTo.contains(key)) {
            return;
        }
        this.flowsTo.add(key);
    }
}
