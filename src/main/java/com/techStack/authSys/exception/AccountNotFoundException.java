package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class AccountNotFoundException extends CustomException {
    public AccountNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}