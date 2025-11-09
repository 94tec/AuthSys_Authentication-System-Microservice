package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Email service exception
 */
public class EmailServiceException extends CustomException {
    public EmailServiceException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public EmailServiceException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}
