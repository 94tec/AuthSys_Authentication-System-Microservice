package com.techStack.authSys.exception.security;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Suspicious activity detected exception
 */
public class SuspiciousActivityException extends CustomException {
    public SuspiciousActivityException(String reason) {
        super(HttpStatus.FORBIDDEN,
                "Suspicious activity detected: " + reason);
    }
}
