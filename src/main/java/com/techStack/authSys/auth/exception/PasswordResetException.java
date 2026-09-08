package com.techStack.authSys.auth.exception;


import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class PasswordResetException extends CustomException {
    public PasswordResetException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}