package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class InvalidPaginationParameterException extends CustomException {
    public InvalidPaginationParameterException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
