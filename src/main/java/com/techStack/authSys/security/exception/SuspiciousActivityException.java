package com.techStack.authSys.security.exception;

import com.techStack.authSys.common.exception.CustomException;
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
