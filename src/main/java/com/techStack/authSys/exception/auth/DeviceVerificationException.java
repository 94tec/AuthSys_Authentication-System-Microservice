package com.techStack.authSys.exception.auth;

public class DeviceVerificationException extends RuntimeException {
    public DeviceVerificationException(String message) {
        super(message);
    }

    public DeviceVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}