package com.firmrec.model;

import com.firmrec.utils.StringUtils;

import java.util.ArrayList;
import java.util.Objects;

public class ProgramSourceSink {
    private String entryFunctionId;
    private long entryAddress;
    private ArrayList<Long> sourceAddresses;
    private ArrayList<Long> sinkAddresses;
    private int sourceIndex;
    private int sinkIndex;

    public ProgramSourceSink(String entryFunctionId, long entryAddress, ArrayList<Long> sourceAddresses, ArrayList<Long> sinkAddresses, int sourceIndex, int sinkIndex) {
        this.entryFunctionId = entryFunctionId;
        this.entryAddress = entryAddress;
        this.sourceAddresses = sourceAddresses;
        this.sinkAddresses = sinkAddresses;
        this.sourceIndex = sourceIndex;
        this.sinkIndex = sinkIndex;
    }

    public String getEntryFunctionId() {
        return this.entryFunctionId;
    }

    public long getEntryAddress() {
        return this.entryAddress;
    }

    public ArrayList<Long> getSourceAddresses() {
        return this.sourceAddresses;
    }

    public ArrayList<Long> getSinkAddresses() {
        return this.sinkAddresses;
    }

    public int getSourceIndex() {
        return this.sourceIndex;
    }

    public int getSinkIndex() {
        return this.sinkIndex;
    }

    @Override
    public String toString() {
        StringBuilder description = new StringBuilder();
        description.append("Entry Function: ").append(this.getEntryFunctionId()).append(" (").append(this.sourceIndex).append(")").append("\n");
//        description.append("\t").append(StringUtils.convertHexString(this.getEntryAddress(), 16));
        for (int i = 0; i < this.getSourceAddresses().size(); ++i) {
            Long tmpAddress = this.getSourceAddresses().get(i);
            description.append(" -> ").append(StringUtils.convertHexString(tmpAddress, 16));
        }
        description.append(" (").append(this.sourceIndex).append(")");
        description.append("\n");

        description.append("\t||\n");
        description.append("\t||\n");
        description.append("\t\\/\n");

        for (int i = 1; i < this.getSinkAddresses().size(); ++i) {
            Long tmpAddress = this.getSinkAddresses().get(i);
            description.append(" -> ").append(StringUtils.convertHexString(tmpAddress, 16));
        }
        description.append(" (").append(this.sinkIndex).append(")");
        return description.toString();
    }

    @Override
    public boolean equals(Object obj) {
        ProgramSourceSink other = (ProgramSourceSink) obj;
        if (!Objects.equals(this.entryFunctionId, other.entryFunctionId)) return false;
        if (this.sourceIndex != other.sourceIndex) return false;
        if (this.sinkIndex != other.sinkIndex) return false;
        if (this.sourceAddresses.size() != other.getSourceAddresses().size()) return false;
        for (int i = 0; i < this.sourceAddresses.size(); ++i) {
            if (!Objects.equals(this.sourceAddresses.get(i), other.getSourceAddresses().get(i))) return false;
        }
        if (this.sinkAddresses.size() != other.sinkAddresses.size()) return false;
        for (int i = 0; i < this.sinkAddresses.size(); ++i) {
            if (!Objects.equals(this.sinkAddresses.get(i), other.getSinkAddresses().get(i))) return false;
        }
        return true;
    }
}
