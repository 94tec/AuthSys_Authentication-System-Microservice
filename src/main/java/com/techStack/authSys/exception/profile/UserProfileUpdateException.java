package com.techStack.authSys.exception.profile;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class UserProfileUpdateException extends CustomException {
    public UserProfileUpdateException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }
}