package com.techStack.authSys.auth.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Email already exists exception
 */
public class EmailAlreadyExistsException extends CustomException {
    public EmailAlreadyExistsException(String email) {
        super(HttpStatus.CONFLICT, "Email address already registered: " + email);
    }
}
