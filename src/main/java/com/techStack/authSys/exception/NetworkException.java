package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class NetworkException extends CustomException {
    public NetworkException(String message) {
        super(HttpStatus.SERVICE_UNAVAILABLE, message);
    }

    public NetworkException(String message, Throwable cause) {
        super(HttpStatus.SERVICE_UNAVAILABLE, message, cause);
    }
}