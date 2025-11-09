package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Common password exception
 */
public class CommonPasswordException extends CustomException {
    public CommonPasswordException() {
        super(HttpStatus.BAD_REQUEST,
                "Password is too common. Please choose a more unique password.");
    }
}
