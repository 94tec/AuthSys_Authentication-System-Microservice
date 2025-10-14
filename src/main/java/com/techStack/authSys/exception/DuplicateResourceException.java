package com.techStack.authSys.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class DuplicateResourceException extends ResponseStatusException {
    public DuplicateResourceException(HttpStatus status, String message) {
        super(status, message);
    }
    public DuplicateResourceException(HttpStatus status, String message, Throwable cause) {
        super(status,message, cause);
    }
}

