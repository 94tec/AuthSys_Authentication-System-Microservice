package com.techStack.authSys.exception.profile;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class InvalidUserProfileException extends CustomException {
    public InvalidUserProfileException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
