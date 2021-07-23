package com.freshjuice.isomer.security.multi.adapter;

import org.springframework.security.core.AuthenticationException;

public class PhoneNotFoundAdapterException extends AuthenticationException {
    public PhoneNotFoundAdapterException(String msg, Throwable t) {
        super(msg, t);
    }

    public PhoneNotFoundAdapterException(String msg) {
        super(msg);
    }
}
