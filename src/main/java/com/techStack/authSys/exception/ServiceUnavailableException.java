package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Service unavailable exception
 */
public class ServiceUnavailableException extends CustomException {
    public ServiceUnavailableException(String service) {
        super(HttpStatus.SERVICE_UNAVAILABLE,
                service + " is temporarily unavailable");
    }
}
