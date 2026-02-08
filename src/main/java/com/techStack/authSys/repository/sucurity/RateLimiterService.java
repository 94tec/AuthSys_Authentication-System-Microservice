package com.techStack.authSys.repository.sucurity;

import com.google.cloud.Timestamp;
import com.techStack.authSys.dto.internal.SessionRecord;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public interface RateLimiterService {
    Mono<Void> checkAuthRateLimit(String ipAddress, String email);
    Mono<Boolean> recordFailedAttempt(String email, String ipAddress);

    Mono<Object> checkThreatApiRateLimit(String ipAddress);

}