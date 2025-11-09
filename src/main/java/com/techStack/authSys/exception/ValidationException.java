package com.techStack.authSys.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.Map;

/**
 * Validation exception with field information
 */
@Getter
public class ValidationException extends CustomException {
    private final String field;
    //private final Map<String, String> validationErrors;
    private final Map<String, Object> validationErrors;

    public ValidationException(String message, String field) {
        super(HttpStatus.BAD_REQUEST, message);
        this.field = field;
        this.validationErrors = null;
    }

    public ValidationException(String message, Map<String, Object> validationErrors) {
        super(HttpStatus.BAD_REQUEST, message);
        this.field = null;
        this.validationErrors = validationErrors;
    }

}
