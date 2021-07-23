package com.freshjuice.isomer.common.enums;

public enum JsonResultEnum {
    SUCCESS("1", "SUCCESS"),
    FAIL("-1", "FAIL"),
    AUTHENTICATION_NEED("401", "401"),
    PERMISSION_DENIED("403", "403"),
    CSRF_TOKEN_FAIL("405", "405");

    private String code;
    private String text;

    JsonResultEnum(String code, String text) {
        this.code = code;
        this.text = text;
    }

    public String getCode() {
        return code;
    }
    public String getText() {
        return text;
    }
}
