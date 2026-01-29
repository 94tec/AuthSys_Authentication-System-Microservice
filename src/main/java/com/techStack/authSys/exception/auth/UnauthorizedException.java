package com.techStack.authSys.exception.auth;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class UnauthorizedException extends CustomException {
    public UnauthorizedException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
    }

    public UnauthorizedException(String message, Throwable cause) {
        super(HttpStatus.UNAUTHORIZED, message, cause);
    }
}