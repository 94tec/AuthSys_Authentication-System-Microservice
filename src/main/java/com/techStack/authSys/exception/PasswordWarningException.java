package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class PasswordWarningException extends CustomException {
    public PasswordWarningException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}