package com.techStack.authSys.exception.password;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class PasswordResetException extends CustomException {
    public PasswordResetException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}