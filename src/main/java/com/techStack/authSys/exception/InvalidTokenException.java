package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class InvalidTokenException extends CustomException {
    public InvalidTokenException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(HttpStatus.UNAUTHORIZED, message, cause);
    }
}