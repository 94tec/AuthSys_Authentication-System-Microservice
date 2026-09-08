package com.techStack.authSys.auth.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class PasswordUpdateException extends CustomException {
    public PasswordUpdateException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}