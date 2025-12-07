package com.techStack.authSys.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus; // 💡 Need to import HttpStatus

@Getter
public class FirebaseRestAuthException extends CustomException {
    private final String errorCode;

    /**
     * Constructor for an exception wrapping an error from the Firebase Auth REST API.
     * Sets the HTTP status to 400 (BAD_REQUEST) as a general client-side error.
     *
     * @param errorCode The specific error code returned by Firebase (e.g., "EMAIL_EXISTS").
     * @param message The user-facing message derived from the Firebase error.
     */
    public FirebaseRestAuthException(String errorCode, String message) {
        // 🟢 FIX: Pass the appropriate HTTP Status (400 BAD_REQUEST) to the parent constructor.
        super(HttpStatus.BAD_REQUEST, message);
        this.errorCode = errorCode;
    }

    // Optional: Add a constructor for specific status codes if needed later
    public FirebaseRestAuthException(HttpStatus status, String errorCode, String message) {
        super(status, message);
        this.errorCode = errorCode;
    }
}