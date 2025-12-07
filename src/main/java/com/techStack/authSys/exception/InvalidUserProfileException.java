package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class InvalidUserProfileException extends CustomException {
    public InvalidUserProfileException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
