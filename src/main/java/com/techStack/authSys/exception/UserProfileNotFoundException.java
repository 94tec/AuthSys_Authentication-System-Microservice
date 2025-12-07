package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class UserProfileNotFoundException extends CustomException {
    public UserProfileNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}