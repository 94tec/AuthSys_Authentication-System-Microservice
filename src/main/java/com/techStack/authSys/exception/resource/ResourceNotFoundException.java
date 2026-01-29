package com.techStack.authSys.exception.resource;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends ResponseStatusException {
    public ResourceNotFoundException(HttpStatus status, String message) {
        super(status, message);
    }
    public ResourceNotFoundException(HttpStatus status, String message, Throwable cause) {
        super(status,message, cause);
    }
}
