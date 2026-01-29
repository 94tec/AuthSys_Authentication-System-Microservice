package com.techStack.authSys.exception.service;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Custom exception with field-level details for reactive apps.
 */
@Getter
public class CustomException extends RuntimeException {
    private final HttpStatus status;
    private final String field;
    private final String code;

    public CustomException(HttpStatus status, String message) {
        super(message);
        this.status = status;
        this.field = null;
        this.code = null;
    }
    public CustomException(HttpStatus status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
        this.field = null;
        this.code = null;
    }

    public CustomException(HttpStatus status, String message, String field, String code) {
        super(message);
        this.status = status;
        this.field = field;
        this.code = code;
    }

    public CustomException(HttpStatus status, String message, Throwable cause, String field, String code) {
        super(message, cause);
        this.status = status;
        this.field = field;
        this.code = code;
    }

    @Override
    public String toString() {
        return "CustomException{" +
                "status=" + status +
                ", field='" + field + '\'' +
                ", code='" + code + '\'' +
                ", message='" + getMessage() + '\'' +
                '}';
    }

}
