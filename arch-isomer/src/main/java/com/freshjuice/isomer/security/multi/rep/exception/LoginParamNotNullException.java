package com.freshjuice.isomer.security.multi.rep.exception;

import org.springframework.security.core.AuthenticationException;

public class LoginParamNotNullException extends AuthenticationException {
    public LoginParamNotNullException(String msg, Throwable t) {
        super(msg, t);
    }

    public LoginParamNotNullException(String msg) {
        super(msg);
    }
}
