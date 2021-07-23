package com.freshjuice.isomer.security.multi.rep.exception;

import org.springframework.security.core.AuthenticationException;

public class UnSupportedLoginTypeException extends AuthenticationException {
    public UnSupportedLoginTypeException(String msg, Throwable t) {
        super(msg, t);
    }

    public UnSupportedLoginTypeException(String msg) {
        super(msg);
    }
}
