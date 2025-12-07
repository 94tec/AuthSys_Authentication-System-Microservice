package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class UserProfileUpdateException extends CustomException {
    public UserProfileUpdateException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }
}