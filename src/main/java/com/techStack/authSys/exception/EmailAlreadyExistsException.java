package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Email already exists exception
 */
public class EmailAlreadyExistsException extends CustomException {
    public EmailAlreadyExistsException(String email) {
        super(HttpStatus.CONFLICT, "Email address already registered: " + email);
    }
}
