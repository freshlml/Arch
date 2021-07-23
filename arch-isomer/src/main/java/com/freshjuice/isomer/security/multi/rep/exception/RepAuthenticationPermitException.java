package com.freshjuice.isomer.security.multi.rep.exception;

import org.springframework.security.core.AuthenticationException;

public class RepAuthenticationPermitException extends AuthenticationException {
    public RepAuthenticationPermitException(String msg, Throwable t) {
        super(msg, t);
    }

    public RepAuthenticationPermitException(String msg) {
        super(msg);
    }
}
