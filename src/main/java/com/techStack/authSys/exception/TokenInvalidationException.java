package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class TokenInvalidationException extends CustomException {
    public TokenInvalidationException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}