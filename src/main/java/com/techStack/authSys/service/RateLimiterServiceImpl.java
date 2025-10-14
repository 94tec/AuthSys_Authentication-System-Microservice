package com.techStack.authSys.service;

import com.google.cloud.firestore.*;
import com.techStack.authSys.exception.RateLimitExceededException;
import com.techStack.authSys.models.RateLimitRecord;
import com.techStack.authSys.repository.BlacklistService;
import com.techStack.authSys.repository.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimiterServiceImpl implements RateLimiterService {

    private static final String RATE_LIMIT_COLLECTION = "auth_rate_limits";
    private static final String IP_BLACKLIST_COLLECTION = "ip_blacklist";

    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final GeoLocationService geoLocationService;
    private final JwtService jwtService;
    private final CacheService cacheService;
    private final BlacklistService blacklistService;

    @Value("${security.rate-limiter.auth.max-per-minute:5}")
    private int maxAttemptsPerMinute;

    @Value("${security.rate-limiter.auth.max-per-hour:20}")
    private int maxAttemptsPerHour;

    @Value("${security.rate-limiter.auth.ip-blacklist-duration:24}")
    private int blacklistDurationHours;

    @Value("${security.rate-limiter.auth.account-lock-threshold:5}")
    private int accountLockThreshold;

    @Override
    public Mono<Void> checkAuthRateLimit(String ipAddress, String email) {
        return Mono.defer(() -> {
            Instant now = Instant.now();
            return blacklistService.isBlacklisted(ipAddress)
                    .flatMap(blacklisted -> {
                        if (blacklisted) {
                            return Mono.error(new RateLimitExceededException("Too many requests. Try again later."));
                        }
                        return Mono.zip(
                                cacheService.getRateLimitRecord(ipAddress, "ip"),
                                cacheService.getRateLimitRecord(email, "email")
                        );
                    })
                    .flatMap(tuple -> {
                        RateLimitRecord ipRecord = tuple.getT1();
                        RateLimitRecord emailRecord = tuple.getT2();

                        if (ipRecord.getMinuteCount() >= maxAttemptsPerMinute || emailRecord.getMinuteCount() >= maxAttemptsPerMinute) {
                            return handleRateLimitExceeded(ipAddress, email, "minute");
                        }
                        if (ipRecord.getHourCount() >= maxAttemptsPerHour || emailRecord.getHourCount() >= maxAttemptsPerHour) {
                            return handleRateLimitExceeded(ipAddress, email, "hour");
                        }
                        return cacheService.updateRateLimitCounts(ipAddress, email, ipRecord, emailRecord);
                    });
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> handleRateLimitExceeded(String ipAddress, String email, String timeframe) {
        log.warn("Rate limit exceeded for {} - {}", email, timeframe);
        auditLogService.logSecurityEvent("RATE_LIMIT_EXCEEDED", ipAddress, "User exceeded " + timeframe + " rate limit");
        return blacklistService.blacklistIp(ipAddress).then()
                .then(Mono.error(new RateLimitExceededException("Too many requests. Try again later.")));
    }

    @Override
    public Mono<Boolean> recordFailedAttempt(String email, String ipAddress) {
        return cacheService.getRateLimitRecord(email, "email")
                .flatMap(record -> {
                    record.incrementFailedAttempts();
                    boolean shouldLockAccount = record.getFailedAttempts() >= accountLockThreshold;
                    return cacheService.updateRateLimitRecord(email, "email", record)
                            .thenReturn(shouldLockAccount);
                });
    }

    @Override
    public Mono<Object> checkThreatApiRateLimit(String ipAddress) {
        return null;
    }
}
