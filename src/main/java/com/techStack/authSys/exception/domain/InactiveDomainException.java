package com.techStack.authSys.exception.domain;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Inactive domain exception
 */
public class InactiveDomainException extends CustomException {
    public InactiveDomainException(String domain) {
        super(HttpStatus.BAD_REQUEST,
                "Email domain is temporarily inactive: " + domain);
    }
}
