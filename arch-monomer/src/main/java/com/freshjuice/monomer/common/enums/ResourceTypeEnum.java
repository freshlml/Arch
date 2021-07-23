package com.freshjuice.monomer.common.enums;

public enum ResourceTypeEnum {
    MENU("MENU", "菜单资源"),
    DATA("DATA", "数据资源");

    private String value;
    private String text;
    ResourceTypeEnum(String value, String text) {
        this.value = value;
        this.text = text;
    }

}
