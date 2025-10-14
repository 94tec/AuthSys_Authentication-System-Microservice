package com.techStack.authSys.exception;

public class TemporaryPasswordExpiredException extends RuntimeException {
    public TemporaryPasswordExpiredException(String message) {
        super(message);
    }
}
