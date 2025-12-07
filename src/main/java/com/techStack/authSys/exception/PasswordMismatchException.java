package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class PasswordMismatchException extends CustomException {
    public PasswordMismatchException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}