package com.techStack.authSys.exception.account;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class AccountNotFoundException extends CustomException {
    public AccountNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}