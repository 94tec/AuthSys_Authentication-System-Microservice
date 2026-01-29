package com.techStack.authSys.exception.auth;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class TokenGenerationException extends CustomException {
    public TokenGenerationException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}
