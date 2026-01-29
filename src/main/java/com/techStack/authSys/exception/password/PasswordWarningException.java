package com.techStack.authSys.exception.password;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class PasswordWarningException extends CustomException {
    public PasswordWarningException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}