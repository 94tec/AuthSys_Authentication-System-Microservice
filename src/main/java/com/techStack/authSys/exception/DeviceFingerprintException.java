package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Device fingerprint exception
 */
public class DeviceFingerprintException extends CustomException {
    public DeviceFingerprintException(String message) {
        super(HttpStatus.BAD_REQUEST, message);
    }
}
