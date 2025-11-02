package com.techStack.authSys.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;

@Getter
public class AuthException extends RuntimeException {

    private final HttpStatus status;
    private final Instant timestamp;
    private final String errorCode;

    // Basic constructor
    public AuthException(String message, HttpStatus status) {
        super(message);
        this.status = status;
        this.timestamp = Instant.now();
        this.errorCode = generateErrorCode(status);
    }

    // Constructor with cause
    public AuthException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
        this.timestamp = Instant.now();
        this.errorCode = generateErrorCode(status);
    }

    // Constructor with custom error code
    public AuthException(String message, HttpStatus status, String errorCode) {
        super(message);
        this.status = status;
        this.timestamp = Instant.now();
        this.errorCode = errorCode;
    }

    // Full constructor
    public AuthException(String message, Throwable cause, HttpStatus status, String errorCode) {
        super(message, cause);
        this.status = status;
        this.timestamp = Instant.now();
        this.errorCode = errorCode;
    }

    // Helper method to generate standardized error codes
    private String generateErrorCode(HttpStatus status) {
        return "AUTH_" + status.value();
    }

    // Convenience methods for common auth scenarios
    public static AuthException invalidCredentials() {
        return new AuthException(
                "Invalid email or password",
                HttpStatus.UNAUTHORIZED,
                "AUTH_001"
        );
    }

    public static AuthException accountNotFound() {
        return new AuthException(
                "Account not found. Please check your email or register.",
                HttpStatus.UNAUTHORIZED,
                "AUTH_002"
        );
    }

    public static AuthException accountDisabled() {
        return new AuthException(
                "Account has been disabled. Please contact support.",
                HttpStatus.FORBIDDEN,
                "AUTH_003"
        );
    }

    public static AuthException emailNotVerified() {
        return new AuthException(
                "Email not verified. Please check your inbox for verification link.",
                HttpStatus.FORBIDDEN,
                "AUTH_004"
        );
    }

    public static AuthException rateLimitExceeded() {
        return new AuthException(
                "Too many failed attempts. Please try again in 15 minutes.",
                HttpStatus.TOO_MANY_REQUESTS,
                "AUTH_005"
        );
    }

    public static AuthException sessionExpired() {
        return new AuthException(
                "Session expired. Please log in again.",
                HttpStatus.UNAUTHORIZED,
                "AUTH_006"
        );
    }

    public static AuthException mfaRequired() {
        return new AuthException(
                "Multi-factor authentication required.",
                HttpStatus.UNAUTHORIZED,
                "AUTH_007"
        );
    }

    public static AuthException invalidToken() {
        return new AuthException(
                "Invalid or expired token.",
                HttpStatus.UNAUTHORIZED,
                "AUTH_008"
        );
    }

    // Convenience method to get timestamp as Date (for compatibility)
    public Date getTimestampAsDate() {
        return Date.from(timestamp);
    }

    // Convenience method to get timestamp as LocalDateTime
    public LocalDateTime getTimestampAsLocalDateTime() {
        return LocalDateTime.ofInstant(timestamp, java.time.ZoneId.systemDefault());
    }

    @Override
    public String toString() {
        return String.format(
                "AuthException{status=%s, errorCode=%s, message=%s, timestamp=%s}",
                status, errorCode, getMessage(), timestamp
        );
    }
}