package com.techStack.authSys.authorization.exception;

import com.techStack.authSys.common.exception.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Permission denied exception
 */
public class PermissionDeniedException extends CustomException {
    public PermissionDeniedException(String message) {
        super(HttpStatus.FORBIDDEN, message);
    }
}
