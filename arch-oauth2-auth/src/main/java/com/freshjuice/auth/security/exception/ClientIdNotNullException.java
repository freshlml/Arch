package com.freshjuice.auth.security.exception;

import org.springframework.security.core.AuthenticationException;

public class ClientIdNotNullException extends AuthenticationException {
    public ClientIdNotNullException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public ClientIdNotNullException(String msg) {
        super(msg);
    }
}
