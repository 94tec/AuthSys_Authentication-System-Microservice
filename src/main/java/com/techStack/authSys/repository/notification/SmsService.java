package com.techStack.authSys.repository.notification;

import reactor.core.publisher.Mono;

public interface SmsService {
    Mono<Void> sendOtp(String phoneNumber, String otp);
}

