package com.techStack.authSys.exception.profile;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class UserProfileNotFoundException extends CustomException {
    public UserProfileNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}