package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class EmailAlreadyExistsException extends ResponseStatusException {

    public EmailAlreadyExistsException() {
        super(HttpStatus.CONFLICT, "Email already exists");
    }

    public EmailAlreadyExistsException(HttpStatus status, String message) {
        super(status, message);
    }

    public EmailAlreadyExistsException(HttpStatus status, String message, Throwable cause) {
        super(status, message, cause);
    }
}
