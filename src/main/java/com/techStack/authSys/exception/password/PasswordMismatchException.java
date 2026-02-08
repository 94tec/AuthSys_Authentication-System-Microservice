package com.techStack.authSys.exception.password;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Password Mismatch Exception
 *
 * Thrown when current password verification fails during password change.
 */
public class PasswordMismatchException extends CustomException {

    /**
     * Constructor with message
     */
    public PasswordMismatchException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
    }

    /**
     * Constructor with HTTP status and message
     */
    public PasswordMismatchException(HttpStatus status, String message) {
        super(status, message);
    }

    /**
     * Constructor with HTTP status and cause
     */
    public PasswordMismatchException(HttpStatus status, Throwable cause) {
        super(status, String.valueOf(cause));
    }

    /**
     * Constructor with message and cause
     */
    public PasswordMismatchException(String message, Throwable cause) {
        super(HttpStatus.UNAUTHORIZED, message, cause);
    }
}