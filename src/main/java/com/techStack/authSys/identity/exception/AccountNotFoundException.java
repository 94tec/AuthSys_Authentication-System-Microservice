package com.techStack.authSys.identity.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class AccountNotFoundException extends CustomException {
    public AccountNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}