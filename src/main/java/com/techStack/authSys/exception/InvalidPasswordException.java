package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

public class InvalidPasswordException extends CustomException  {
    public InvalidPasswordException(HttpStatus status, String message) {
        super(status, message);
    }

    public InvalidPasswordException(HttpStatus status, String message, Throwable cause) {
        super(status, message, cause);
    }

    public InvalidPasswordException(HttpStatus status, String message, String field, String code) {
        super(status, message, field, code);
    }

    public InvalidPasswordException(HttpStatus status, String message, Throwable cause, String field, String code) {
        super(status, message, cause, field, code);
    }

}
