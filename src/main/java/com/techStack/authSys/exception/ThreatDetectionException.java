package com.techStack.authSys.exception;

public class ThreatDetectionException extends RuntimeException {
    public ThreatDetectionException(String message) {
        super(message);
    }

    public ThreatDetectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
