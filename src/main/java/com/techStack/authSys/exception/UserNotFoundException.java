package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

// Custom Exception: UserNotFoundException.java
public class UserNotFoundException extends ResponseStatusException {

    public UserNotFoundException(HttpStatus status, String message) {
        super(status, message);
    }
    public UserNotFoundException(HttpStatus status, String message, Throwable cause) {
        super(status,message, cause);
    }

    public UserNotFoundException(String userId) {
        super(HttpStatus.NOT_FOUND, "User not found with ID: " + userId);
    }
}
