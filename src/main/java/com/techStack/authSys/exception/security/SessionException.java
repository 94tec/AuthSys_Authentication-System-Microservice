package com.techStack.authSys.exception.security;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class SessionException extends CustomException {
    public SessionException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public SessionException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}
