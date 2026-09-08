package com.techStack.authSys.identity.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class UserProfileUpdateException extends CustomException {
    public UserProfileUpdateException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }
}