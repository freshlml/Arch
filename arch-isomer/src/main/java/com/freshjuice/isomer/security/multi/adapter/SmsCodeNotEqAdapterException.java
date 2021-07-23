package com.freshjuice.isomer.security.multi.adapter;

import org.springframework.security.core.AuthenticationException;

public class SmsCodeNotEqAdapterException extends AuthenticationException {
    public SmsCodeNotEqAdapterException(String msg, Throwable t) {
        super(msg, t);
    }

    public SmsCodeNotEqAdapterException(String msg) {
        super(msg);
    }
}
