package com.techStack.authSys.exception.email;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class EmailAlreadyVerifiedException extends ResponseStatusException {
    public EmailAlreadyVerifiedException(HttpStatus status, String message) {
        super(status, message);
    }

    public EmailAlreadyVerifiedException(HttpStatus status, String message, Throwable cause) {
        super(status,message, cause);
    }
}