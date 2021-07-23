package com.freshjuice.isomer.security.multi.adapter;

import org.springframework.security.core.AuthenticationException;

public class SmsCodeInvalidAdapterException extends AuthenticationException {
    public SmsCodeInvalidAdapterException(String msg, Throwable t) {
        super(msg, t);
    }

    public SmsCodeInvalidAdapterException(String msg) {
        super(msg);
    }
}
