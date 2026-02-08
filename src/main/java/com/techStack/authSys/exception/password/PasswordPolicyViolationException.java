package com.techStack.authSys.exception.password;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Password Policy Violation Exception
 *
 * Thrown when password doesn't meet policy requirements
 * (complexity, length, history, etc.).
 */
public class PasswordPolicyViolationException extends CustomException {

    /**
     * Constructor with message
     */
    public PasswordPolicyViolationException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }

    /**
     * Constructor with HTTP status and message
     */
    public PasswordPolicyViolationException(HttpStatus status, String message) {
        super(status, message);
    }

    /**
     * Constructor with HTTP status and cause
     */
    public PasswordPolicyViolationException(HttpStatus status, Throwable cause) {
        super(status, String.valueOf(cause));
    }

    /**
     * Constructor with message and cause
     */
    public PasswordPolicyViolationException(String message, Throwable cause) {
        super(HttpStatus.BAD_REQUEST, message, cause);
    }
}