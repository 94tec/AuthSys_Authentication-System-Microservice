package com.techStack.authSys.identity.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class InvalidUserProfileException extends CustomException {
    public InvalidUserProfileException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
