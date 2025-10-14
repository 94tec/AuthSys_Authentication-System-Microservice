package com.techStack.authSys.exception;

public class ExcessiveAttemptsException extends RuntimeException {
    public ExcessiveAttemptsException(String message) {
        super(message);
    }
}
