package com.techStack.authSys.exception.resource;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class InvalidPaginationParameterException extends CustomException {
    public InvalidPaginationParameterException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
