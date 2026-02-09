package com.techStack.authSys.exception.bootstrap;

/**
 * Fatal bootstrap exception that should halt application startup.
 */
public class BootstrapInitializationException extends RuntimeException {
    private final String failurePoint;
    private final boolean retryable;

    public BootstrapInitializationException(String message, String failurePoint) {
        super(message);
        this.failurePoint = failurePoint;
        this.retryable = false;
    }

    public BootstrapInitializationException(String message, String failurePoint, Throwable cause, boolean retryable) {
        super(message, cause);
        this.failurePoint = failurePoint;
        this.retryable = retryable;
    }

    public String getFailurePoint() {
        return failurePoint;
    }

    public boolean isRetryable() {
        return retryable;
    }
}
