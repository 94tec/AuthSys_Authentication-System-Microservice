package com.techStack.authSys.auth.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus; // 💡 Need to import HttpStatus

public class AuthenticationException extends CustomException {

    /**
     * Constructor for an authentication failure exception.
     * Sets the HTTP status to 401 (UNAUTHORIZED).
     *
     * @param message The user-facing message (e.g., "Invalid credentials").
     */
    public AuthenticationException(String message) {
        // 🟢 FIX: Pass the 401 UNAUTHORIZED status to the parent constructor.
        super(HttpStatus.UNAUTHORIZED, message);
    }
}