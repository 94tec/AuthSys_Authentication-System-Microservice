package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class TemporaryPasswordExpiredException extends CustomException {
    public TemporaryPasswordExpiredException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
    }
}
