package com.techStack.authSys.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Getter
public class CustomException extends ResponseStatusException {
    private final HttpStatus status;

    // Constructor with status and reason
    public CustomException(HttpStatus status, String reason) {
        super(status, reason);
        this.status = status;
    }

    // Constructor with status, reason, and cause
    public CustomException(HttpStatus status, String reason, Throwable cause) {
        super(status, reason, cause);
        this.status = status;
    }

    // Getter for status (if needed)
    @Override
    public HttpStatus getStatusCode() {
        return this.status;
    }
}

