package com.techStack.authSys.exception.account;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class InvalidUserIdException extends CustomException {
    public InvalidUserIdException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}