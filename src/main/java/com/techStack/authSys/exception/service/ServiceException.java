package com.techStack.authSys.exception.service;

import org.springframework.http.HttpStatus;

public class ServiceException extends CustomException {
    public ServiceException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public ServiceException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}