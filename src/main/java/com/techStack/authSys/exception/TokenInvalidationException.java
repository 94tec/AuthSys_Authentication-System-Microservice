package com.techStack.authSys.exception;

public class TokenInvalidationException extends RuntimeException {
    public TokenInvalidationException(String message, Throwable cause) { super(message, cause); }
}