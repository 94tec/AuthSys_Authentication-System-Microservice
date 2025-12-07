package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class InvalidUserDetailsException extends CustomException {
    public InvalidUserDetailsException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
