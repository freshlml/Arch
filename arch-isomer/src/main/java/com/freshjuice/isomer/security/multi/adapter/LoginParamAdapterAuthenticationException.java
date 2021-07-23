package com.freshjuice.isomer.security.multi.adapter;

import org.springframework.security.core.AuthenticationException;

public class LoginParamAdapterAuthenticationException extends AuthenticationException {
    public LoginParamAdapterAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    public LoginParamAdapterAuthenticationException(String msg) {
        super(msg);
    }
}
