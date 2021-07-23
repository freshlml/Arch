package com.freshjuice.monomer.common.enums;

public enum PrincipalEnum {
    USERNAME("1"),
    PHONE("2");

    private String value;
    PrincipalEnum(String value) {
        this.value = value;
    }
    public String getValue() {
        return value;
    }
}
