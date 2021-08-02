package com.freshjuice.auth.security.exception;

import org.springframework.security.core.AuthenticationException;

public class SmsCodeCheckException extends AuthenticationException {
    public SmsCodeCheckException(String msg, Throwable t) {
        super(msg, t);
    }

    public SmsCodeCheckException(String msg) {
        super(msg);
    }
}
