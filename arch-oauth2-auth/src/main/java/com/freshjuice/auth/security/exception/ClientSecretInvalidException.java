package com.freshjuice.auth.security.exception;

import org.springframework.security.core.AuthenticationException;

public class ClientSecretInvalidException extends AuthenticationException {
    public ClientSecretInvalidException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public ClientSecretInvalidException(String msg) {
        super(msg);
    }
}
