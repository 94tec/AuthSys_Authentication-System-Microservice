package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class InvalidUserIdException extends CustomException {
    public InvalidUserIdException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}