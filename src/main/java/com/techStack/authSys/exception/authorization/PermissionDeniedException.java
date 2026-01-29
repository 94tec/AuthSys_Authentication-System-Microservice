package com.techStack.authSys.exception.authorization;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Permission denied exception
 */
public class PermissionDeniedException extends CustomException {
    public PermissionDeniedException(String message) {
        super(HttpStatus.FORBIDDEN, message);
    }
}
