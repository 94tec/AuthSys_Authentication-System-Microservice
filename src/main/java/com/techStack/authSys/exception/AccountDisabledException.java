package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class AccountDisabledException extends CustomException {
    public AccountDisabledException(String message) {
        super(HttpStatus.FORBIDDEN, message);
    }

    public AccountDisabledException(String message, Throwable cause) {
        super(HttpStatus.FORBIDDEN, message, cause);
    }
}