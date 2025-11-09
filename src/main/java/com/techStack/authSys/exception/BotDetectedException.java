package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Bot detected exception
 */
public class BotDetectedException extends CustomException {
    public BotDetectedException() {
        super(HttpStatus.BAD_REQUEST, "Automated submission detected");
    }
}
