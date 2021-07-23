package com.freshjuice.monomer.common.exception;

public class FlRootException extends RuntimeException {
    public FlRootException() {
    }

    public FlRootException(String message) {
        super(message);
    }

    public FlRootException(String message, Throwable cause) {
        super(message, cause);
    }

    public FlRootException(Throwable cause) {
        super(cause);
    }

    public FlRootException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
