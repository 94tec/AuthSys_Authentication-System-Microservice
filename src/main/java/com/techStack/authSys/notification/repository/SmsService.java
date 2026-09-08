package com.techStack.authSys.notification.repository;

import reactor.core.publisher.Mono;

public interface SmsService {
    Mono<Void> sendOtp(String phoneNumber, String otp);
}

