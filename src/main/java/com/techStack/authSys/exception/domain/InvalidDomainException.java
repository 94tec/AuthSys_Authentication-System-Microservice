package com.techStack.authSys.exception.domain;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Invalid domain exception
 */
public class InvalidDomainException extends CustomException {
    private final String domain;

    public InvalidDomainException(String domain) {
        super(HttpStatus.BAD_REQUEST,
                "Email domain not allowed: " + domain);
        this.domain = domain;
    }

    public String getDomain() {
        return domain;
    }
}
