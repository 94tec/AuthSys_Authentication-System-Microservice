package com.techStack.authSys.identity.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class UserProfileNotFoundException extends CustomException {
    public UserProfileNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}