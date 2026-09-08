package com.techStack.authSys.auth.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class TokenNotFoundException extends CustomException {
    public TokenNotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, message);
    }
}
