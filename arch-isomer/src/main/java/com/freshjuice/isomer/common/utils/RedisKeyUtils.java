package com.freshjuice.isomer.common.utils;

public abstract class RedisKeyUtils {
    private static final String SMS_CODE = "sms:code:%s";


    public static String getSmsCode(String phone) {
        return String.format(SMS_CODE, phone);
    }

}
