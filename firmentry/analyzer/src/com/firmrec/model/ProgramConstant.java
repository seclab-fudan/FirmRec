package com.firmrec.model;

public class ProgramConstant {
    public enum Type {
        INT, FLOAT, STRING, RELREG, ADDR, UNKNOWN
    }

    private Type type;
    private Long intValue = null;
    private String stringValue = null;
    private Double floatValue = null;

    public static final ProgramConstant Unknown = new ProgramConstant(Type.UNKNOWN, null, null, null);

    public Type getType() {
        return type;
    }

    public Long getIntValue() {
        return intValue;
    }

    public String getStringValue() {
        return stringValue;
    }

    public Double getFloatValue() {
        return floatValue;
    }

    public static ProgramConstant createInt(Long intValue) {
        return new ProgramConstant(Type.INT, intValue, null, null);
    }

    public static ProgramConstant createFloat(Double floatValue) {
        return new ProgramConstant(Type.FLOAT, null, null, floatValue);
    }

    public static ProgramConstant createString(String stringValue) {
        return new ProgramConstant(Type.STRING, null, stringValue, null);
    }

    public static ProgramConstant createRelArg(String arg, Long offset) {
        return new ProgramConstant(Type.RELREG, offset, arg, null);
    }

    public static ProgramConstant createAddr(Long addr) {
        return new ProgramConstant(Type.ADDR, addr, null, null);
    }

    protected ProgramConstant(Type type, Long intValue, String stringValue, Double floatValue) {
        this.type = type;
        this.intValue = intValue;
        this.stringValue = stringValue;
        this.floatValue = floatValue;
    }

    public boolean isInt() {
        return this.type == Type.INT;
    }

    public boolean isFloat() {
        return this.type == Type.FLOAT;
    }

    public boolean isString() {
        return this.type == Type.STRING;
    }

    public boolean isRelArg() {
        return this.type == Type.RELREG;
    }

    public boolean isAddr() {
        return this.type == Type.ADDR;
    }

    public boolean isUnknown() {
        return this.type == Type.UNKNOWN;
    }

    public boolean maybeOutputPointer() {
        return this.isAddr() || this.isRelArg() || this.isUnknown();
    }

    @Override
    public String toString() {
        switch (this.type) {
            case INT:
                return this.intValue.toString();
            case FLOAT:
                return this.floatValue.toString();
            case STRING:
                return "\"" + this.stringValue + "\"";
            case RELREG:
                if (this.intValue == 0)
                    return "[" + this.stringValue + "]";
                else if (this.intValue > 0)
                    return "[" + this.stringValue + "+" + this.intValue.toString() + "]";
                else
                    return "[" + this.stringValue + this.intValue.toString() + "]";
            case ADDR:
                return "[0x" + Long.toHexString(this.intValue) + "]";
            default:
                return "[N]"; // NOT DETERMINED
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof ProgramConstant)) {
            return false;
        }
        ProgramConstant other = (ProgramConstant) obj;
        if (this.type != other.type) {
            return false;
        }
        return this.toString().equals(other.toString());
    }

    @Override
    public int hashCode() {
        return this.toString().hashCode();
    }
}
