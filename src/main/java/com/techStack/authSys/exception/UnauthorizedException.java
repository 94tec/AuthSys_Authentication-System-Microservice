package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(HttpStatus status, String message) {
        super();
    }
    public UnauthorizedException(HttpStatus status, String message, Throwable cause) {
        super();
    }

}
