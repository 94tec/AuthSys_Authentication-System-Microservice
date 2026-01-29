package com.techStack.authSys.exception.data;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Cache exception
 */
public class CacheException extends CustomException {
    public CacheException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public CacheException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}
