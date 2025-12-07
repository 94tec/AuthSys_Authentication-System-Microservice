package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class RedisOperationException extends CustomException {
    public RedisOperationException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public RedisOperationException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}