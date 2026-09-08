package com.techStack.authSys.auth.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class TransientAuthenticationException extends CustomException {
    public TransientAuthenticationException(String message) {
        super(HttpStatus.SERVICE_UNAVAILABLE, message);
    }

    public TransientAuthenticationException(String message, Throwable cause) {
        super(HttpStatus.SERVICE_UNAVAILABLE, message, cause);
    }
}