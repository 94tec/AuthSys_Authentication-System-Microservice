package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Database exception
 */
public class DatabaseException extends CustomException {
    public DatabaseException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public DatabaseException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}
