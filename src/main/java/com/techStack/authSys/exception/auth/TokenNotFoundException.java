package com.techStack.authSys.exception.auth;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class TokenNotFoundException extends CustomException {
    public TokenNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}
