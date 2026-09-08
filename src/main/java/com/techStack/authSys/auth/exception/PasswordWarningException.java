package com.techStack.authSys.auth.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class PasswordWarningException extends CustomException {
    public PasswordWarningException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}