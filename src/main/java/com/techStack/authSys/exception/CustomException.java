package com.techStack.authSys.exception;

import lombok.Getter;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Getter
public class CustomException extends ResponseStatusException {
    private final HttpStatus status;
    private final String message;

    // Main constructor with status, reason, and message
    public CustomException(HttpStatus status, String reason, String message) {
        super(status, reason);
        this.status = status;
        this.message = message;
    }

    // Constructor with status, reason, and cause
    public CustomException(HttpStatus status, String reason, Throwable cause, String message) {
        super(status, reason, cause);
        this.status = status;
        this.message = message;
    }

    // Simplified constructor - status and message only (MOST COMMONLY USED)
    public CustomException(HttpStatus status, String message) {
        super(status, message);
        this.status = status;
        this.message = message;
    }

    // Alternative constructor - message first, then status
    public CustomException(String message, HttpStatus status) {
        super(status, message);
        this.status = status;
        this.message = message;
    }

    @NotNull
    @Override
    public HttpStatus getStatusCode() {
        return this.status;
    }

    @NotNull
    @Override
    public String getMessage() {
        return message;
    }

}