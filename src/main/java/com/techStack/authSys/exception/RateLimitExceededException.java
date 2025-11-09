package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Rate limit exceeded exception
 */
public class RateLimitExceededException extends CustomException {
    private final int retryAfterMinutes;

    public RateLimitExceededException(int retryAfterMinutes) {
        super(HttpStatus.TOO_MANY_REQUESTS,
                "Too many registration attempts. Please try again later.");
        this.retryAfterMinutes = retryAfterMinutes;
    }

    public int getRetryAfterMinutes() {
        return retryAfterMinutes;
    }
}
