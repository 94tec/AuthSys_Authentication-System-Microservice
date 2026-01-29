package com.techStack.authSys.exception.security;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

/**
 * Bot detected exception
 */
public class BotDetectedException extends CustomException {
    public BotDetectedException() {
        super(HttpStatus.BAD_REQUEST, "Automated submission detected");
    }
}
