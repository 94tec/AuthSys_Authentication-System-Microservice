package com.techStack.authSys.exception;

import com.google.cloud.Timestamp;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class AuthException extends RuntimeException {

    private final HttpStatus status;
    private final Timestamp timestamp;
    private final String errorCode;

    public AuthException(String message, HttpStatus status) {
        super(message);
        this.status = status;
        this.timestamp = Timestamp.now();
        this.errorCode = null;
    }

    public AuthException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
        this.timestamp = Timestamp.now();
        this.errorCode = null;
    }

    public AuthException(String message, HttpStatus status, String errorCode) {
        super(message);
        this.status = status;
        this.timestamp = Timestamp.now();
        this.errorCode = errorCode;
    }

    public AuthException(String message, Throwable cause, HttpStatus status, String errorCode) {
        super(message, cause);
        this.status = status;
        this.timestamp = Timestamp.now();
        this.errorCode = errorCode;
    }
}
