package com.techStack.authSys.dto.response;

import lombok.Getter;

/**
 * Centralized list of error codes used across the application.
 * Ensures consistency and avoids duplication.
 */
@Getter
public enum ErrorCode {

    // Email-related errors
    EMAIL_ALREADY_EXISTS("EMAIL_ALREADY_EXISTS"),
    INVALID_EMAIL("INVALID_EMAIL"),

    // Password-related errors
    INVALID_CREDENTIALS("INVALID_CREDENTIAL"),
    WEAK_PASSWORD("WEAK_PASSWORD"),
    COMMON_PASSWORD("COMMON_PASSWORD"),

    // Validation errors
    VALIDATION_ERROR("VALIDATION_ERROR"),

    // Security errors
    RATE_LIMIT_EXCEEDED("RATE_LIMIT_EXCEEDED"),
    SUSPICIOUS_ACTIVITY_DETECTED("SUSPICIOUS_ACTIVITY_DETECTED"),
    PERMISSION_DENIED("PERMISSION_DENIED"),
    ACCOUNT_LOCKED("ACCOUNT_LOCKED"),
    ACCOUNT_DISABLED("ACCOUNT_DISABLED"),
    EMAIL_NOT_VERIFIED("EMAIL_NOT_VERIFIED"),
    PASSWORD_EXPIRED("PASSWORD_EXPIRED"),
    INVALID_TOKEN("INVALID_TOKEN"),
    TOKEN_EXPIRED("TOKEN_EXPIRED"),
    NETWORK_ERROR("NETWORK_ERROR"),
    REQUEST_TIMEOUT("REQUEST_TIMEOUT"),
    TRANSIENT_ERROR("TRANSIENT_ERROR"),

    // Domain errors
    INVALID_DOMAIN("INVALID_DOMAIN"),
    INACTIVE_DOMAIN("INACTIVE_DOMAIN"),

    // Service errors
    AUTH_ERROR("AUTH_ERROR"),
    SERVICE_UNAVAILABLE("SERVICE_UNAVAILABLE"),
    DATABASE_ERROR("DATABASE_ERROR"),
    CACHE_ERROR("CACHE_ERROR"),
    DATA_INTEGRITY_ERROR("DATA_INTEGRITY_ERROR"),

    // External provider errors
    FIREBASE_ERROR("FIREBASE_ERROR"),
    EMAIL_SERVICE_ERROR("EMAIL_SERVICE_ERROR"),

    // Fallback
    UNEXPECTED_ERROR("UNEXPECTED_ERROR");

    private final String code;

    ErrorCode(String code) {
        this.code = code;
    }

}
