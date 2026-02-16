package com.techStack.authSys.repository.security;

import reactor.core.publisher.Mono;

public interface RateLimiterService {
    Mono<Void> checkAuthRateLimit(String ipAddress, String email);
    Mono<Boolean> recordFailedAttempt(String email, String ipAddress);

    Mono<Object> checkThreatApiRateLimit(String ipAddress);

    Mono<Void> checkOtpRateLimit(String userId, String otpType);
}