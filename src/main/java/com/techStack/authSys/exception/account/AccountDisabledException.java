package com.techStack.authSys.exception.account;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class AccountDisabledException extends CustomException {
    public AccountDisabledException(String message) {
        super(HttpStatus.FORBIDDEN, message);
    }

    public AccountDisabledException(String message, Throwable cause) {
        super(HttpStatus.FORBIDDEN, message, cause);
    }
}