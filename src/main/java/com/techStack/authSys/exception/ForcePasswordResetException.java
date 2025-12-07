package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus; // 💡 Need to import HttpStatus

public class ForcePasswordResetException extends CustomException {

    /**
     * Constructor for a forced password reset exception.
     * Sets the HTTP status to 403 (FORBIDDEN).
     *
     * @param message The user-facing message explaining why the reset is required.
     */
    public ForcePasswordResetException(String message) {
        // 🟢 FIX: Pass the appropriate HTTP Status (e.g., FORBIDDEN) to the parent constructor.
        super(HttpStatus.FORBIDDEN, message);
    }
}
