package com.techStack.authSys.exception.security;

import com.techStack.authSys.exception.service.CustomException;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Rate limit exceeded exception
 * Thrown when user exceeds rate limits for authentication, OTP, or API requests
 */
@Getter
public class RateLimitExceededException extends CustomException {
    private final int retryAfterMinutes;
    private final String message;

    public RateLimitExceededException(int retryAfterMinutes) {
        super(HttpStatus.TOO_MANY_REQUESTS,
                "Too many attempts. Please try again in " + retryAfterMinutes + " minutes.");
        this.retryAfterMinutes = retryAfterMinutes;
        this.message = "Too many attempts. Please try again in " + retryAfterMinutes + " minutes.";
    }

    public RateLimitExceededException(int retryAfterMinutes, String customMessage) {
        super(HttpStatus.TOO_MANY_REQUESTS, customMessage);
        this.retryAfterMinutes = retryAfterMinutes;
        this.message = customMessage;
    }

    /**
     * Get retry after in seconds (for HTTP headers)
     */
    public long getRetryAfterSeconds() {
        return retryAfterMinutes * 60L;
    }

    /**
     * Get retry after in milliseconds (for Redis TTL)
     */
    public long getRetryAfterMillis() {
        return retryAfterMinutes * 60L * 1000L;
    }

    /**
     * Create exception for IP blacklist
     */
    public static RateLimitExceededException ipBlacklisted() {
        return new RateLimitExceededException(15,
                "Your IP address has been temporarily blocked due to suspicious activity.");
    }

    /**
     * Create exception for account lock
     */
    public static RateLimitExceededException accountLocked() {
        return new RateLimitExceededException(30,
                "Your account has been temporarily locked due to too many failed attempts.");
    }

    /**
     * Create exception for minute rate limit
     */
    public static RateLimitExceededException minuteLimitExceeded() {
        return new RateLimitExceededException(1,
                "Too many attempts. Please wait 1 minute before trying again.");
    }

    /**
     * Create exception for hour rate limit
     */
    public static RateLimitExceededException hourLimitExceeded() {
        return new RateLimitExceededException(60,
                "Too many attempts. Please try again in 1 hour.");
    }

    /**
     * Create exception for OTP rate limit
     */
    public static RateLimitExceededException otpLimitExceeded(String otpType) {
        String type = otpType.equalsIgnoreCase("SETUP") ? "setup" : "login";
        return new RateLimitExceededException(15,
                "Too many " + type + " OTP requests. Please wait 15 minutes.");
    }

    /**
     * Create exception for threat API rate limit
     */
    public static RateLimitExceededException threatApiLimitExceeded() {
        return new RateLimitExceededException(1,
                "Threat detection API rate limit exceeded. Please wait 1 minute.");
    }

    @Override
    public String toString() {
        return String.format("RateLimitExceededException{retryAfterMinutes=%d, message='%s'}",
                retryAfterMinutes, message);
    }
}
