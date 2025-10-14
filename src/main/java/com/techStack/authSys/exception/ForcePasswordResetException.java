package com.techStack.authSys.exception;

public class ForcePasswordResetException extends RuntimeException {
    public ForcePasswordResetException(String message) {
        super(message);
    }
}
