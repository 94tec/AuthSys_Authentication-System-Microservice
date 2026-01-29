package com.techStack.authSys.exception.account;


import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class DuplicateUserException extends ResponseStatusException {
    public DuplicateUserException(HttpStatus status, String message) {
        super(status, message);
    }
    public DuplicateUserException(HttpStatus status, String message, Throwable cause) {
        super(status,message, cause);
    }
}
