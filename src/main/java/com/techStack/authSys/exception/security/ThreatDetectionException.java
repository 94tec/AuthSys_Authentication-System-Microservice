package com.techStack.authSys.exception.security;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class ThreatDetectionException extends CustomException {
    public ThreatDetectionException(String message) {
        super(HttpStatus.FORBIDDEN, message);
    }

    public ThreatDetectionException(String message, Throwable cause) {
        super(HttpStatus.FORBIDDEN, message, cause);
    }
}