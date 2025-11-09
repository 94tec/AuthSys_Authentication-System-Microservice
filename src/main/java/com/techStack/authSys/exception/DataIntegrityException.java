package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Data integrity exception
 */
public class DataIntegrityException extends CustomException {
    public DataIntegrityException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public DataIntegrityException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}
