package com.techStack.authSys.exception.email;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Email already exists exception
 */
public class EmailAlreadyExistsException extends CustomException {
    public EmailAlreadyExistsException(String email) {
        super(HttpStatus.CONFLICT, "Email address already registered: " + email);
    }
}
