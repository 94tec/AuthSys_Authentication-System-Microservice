package com.techStack.authSys.auth.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

public class TemporaryPasswordExpiredException extends CustomException {
    public TemporaryPasswordExpiredException(String message) {
        super(HttpStatus.UNAUTHORIZED, message);
    }
}
