package com.freshjuice.isomer.security.multi.adapter;

import org.springframework.security.core.AuthenticationException;

public class AuthenticationAdapterException extends AuthenticationException {

    public AuthenticationAdapterException(String msg, Throwable t) {
        super(msg, t);
    }

    public AuthenticationAdapterException(String msg) {
        super(msg);
    }
}
