package com.freshjuice.isomer.common.enums;

import com.baomidou.mybatisplus.annotation.EnumValue;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;

import java.util.Arrays;

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum ResourceTypeEnum {
    MENU("MENU", "菜单资源"),
    DATA("DATA", "数据资源");

    @EnumValue
    private String value;
    private String text;

    public String getValue() {
        return value;
    }
    public String getText() {
        return text;
    }
    ResourceTypeEnum(String value, String text) {
        this.value = value;
        this.text = text;
    }

    @JsonCreator
    public static ResourceTypeEnum getByValue(String value) {
        return Arrays.stream(ResourceTypeEnum.values()).filter(en -> en.getValue().equals(value)).findFirst().orElse(null);
    }
}
