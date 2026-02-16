package com.techStack.authSys.service.security;

import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.repository.notification.SmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final SmsService smsService;
    private final Clock clock;

    @Value("${app.env.dev:false}")
    private boolean isDevEnv;

    /* =========================
       Configuration
       ========================= */

    @Value("${otp.setup.validity-minutes:10}")
    private int setupValidityMinutes;

    @Value("${otp.login.validity-minutes:5}")
    private int loginValidityMinutes;

    @Value("${otp.max-attempts:3}")
    private int maxAttempts;

    @Value("${otp.setup.max-requests:5}")
    private int setupMaxRequests;

    @Value("${otp.login.max-requests:10}")
    private int loginMaxRequests;

    @Value("${otp.rate-limit-minutes:15}")
    private int rateLimitMinutes;

    /* =========================
       Constants
       ========================= */

    private static final int OTP_MIN = 100000;
    private static final int OTP_RANGE = 900000;

    // Setup OTP keys
    private static final String SETUP_OTP_KEY = "otp:setup:";
    private static final String SETUP_ATTEMPTS_KEY = "otp:setup:attempts:";
    private static final String SETUP_RATE_LIMIT_KEY = "otp:setup:rate_limit:";

    // Login OTP keys
    private static final String LOGIN_OTP_KEY = "otp:login:";
    private static final String LOGIN_ATTEMPTS_KEY = "otp:login:attempts:";
    private static final String LOGIN_RATE_LIMIT_KEY = "otp:login:rate_limit:";

    /* =========================
       SETUP OTP
       ========================= */

    public Mono<OtpResult> generateAndSendSetupOtp(String userId, String phoneNumber) {
        Instant now = clock.instant();
        log.info("🔐 Generating SETUP OTP for user: {} at {}", userId, now);

        return checkRateLimit(SETUP_RATE_LIMIT_KEY + userId, setupMaxRequests)
                .flatMap(allowed -> {
                    if (!allowed) {
                        log.warn("⚠️ SETUP OTP rate limit exceeded for user: {}", userId);
                        return Mono.just(OtpResult.rateLimited());
                    }

                    String otp = generateOtp();
                    Duration validity = Duration.ofMinutes(setupValidityMinutes);

                    if (isDevEnv) {
                        log.debug("Generated OTP for {}: {}", userId, otp);
                    }

                    return storeOtp(SETUP_OTP_KEY + userId, otp, validity)
                            .then(smsService.sendOtp(phoneNumber, otp))
                            .then(incrementRateLimit(SETUP_RATE_LIMIT_KEY + userId))
                            .thenReturn(OtpResult.sent("First-time setup OTP"))
                            .onErrorResume(ex -> {
                                log.error("❌ Failed to generate/send OTP for user {}: {}", userId, ex.getMessage(), ex);
                                return Mono.just(new OtpResult(false, false, "Failed to send OTP. Try again."));
                            });
                });
    }


    public Mono<OtpVerificationResult> verifySetupOtp(String userId, String enteredOtp) {
        Instant now = clock.instant();
        log.info("🔍 Verifying SETUP OTP for user: {} at {}", userId, now);

        return verifyOtp(
                SETUP_OTP_KEY + userId,
                SETUP_ATTEMPTS_KEY + userId,
                enteredOtp,
                Duration.ofMinutes(setupValidityMinutes),
                "SETUP"
        );
    }

    /* =========================
       LOGIN OTP
       ========================= */

    public Mono<OtpResult> generateAndSendLoginOtp(String userId, String phoneNumber) {
        Instant now = clock.instant();
        log.info("🔐 Generating LOGIN OTP for user: {} at {}", userId, now);

        return checkRateLimit(LOGIN_RATE_LIMIT_KEY + userId, loginMaxRequests)
                .flatMap(allowed -> {
                    if (!allowed) {
                        log.warn("⚠️ LOGIN OTP rate limit exceeded for user: {}", userId);
                        return Mono.just(OtpResult.rateLimited());
                    }

                    String otp = generateOtp();
                    Duration validity = Duration.ofMinutes(loginValidityMinutes);

                    return storeOtp(LOGIN_OTP_KEY + userId, otp, validity)
                            .then(smsService.sendOtp(phoneNumber, otp))
                            .then(incrementRateLimit(LOGIN_RATE_LIMIT_KEY + userId))
                            .thenReturn(OtpResult.sent("Login authentication OTP"));
                });
    }

    public Mono<OtpVerificationResult> verifyLoginOtp(String userId, String enteredOtp) {
        Instant now = clock.instant();
        log.info("🔍 Verifying LOGIN OTP for user: {} at {}", userId, now);

        return verifyOtp(
                LOGIN_OTP_KEY + userId,
                LOGIN_ATTEMPTS_KEY + userId,
                enteredOtp,
                Duration.ofMinutes(loginValidityMinutes),
                "LOGIN"
        );
    }

    /* =========================
       Core OTP Logic
       ========================= */

    private String generateOtp() {
        SecureRandom random = new SecureRandom();
        int otp = OTP_MIN + random.nextInt(OTP_RANGE);
        return String.valueOf(otp);
    }

    private Mono<Void> storeOtp(String key, String otp, Duration validity) {
        return Mono.fromRunnable(() -> {
                    redisTemplate.opsForValue().set(
                            key,
                            otp,
                            validity.toMillis(),
                            TimeUnit.MILLISECONDS
                    );
                    log.debug("💾 OTP stored: {} (expires in {})", key, validity);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    private Mono<OtpVerificationResult> verifyOtp(
            String otpKey,
            String attemptsKey,
            String enteredOtp,
            Duration attemptsTtl,
            String type) {

        return Mono.fromCallable(() -> {
                    String storedOtp = (String) redisTemplate.opsForValue().get(otpKey);

                    if (storedOtp == null) {
                        log.warn("⚠️ {} OTP expired or not found: {}", type, otpKey);
                        return OtpVerificationResult.expired();
                    }

                    if (hasExceededAttempts(attemptsKey)) {
                        log.warn("⚠️ {} OTP max attempts exceeded: {}", type, attemptsKey);
                        deleteOtp(otpKey);
                        return OtpVerificationResult.attemptsExceeded();
                    }

                    if (storedOtp.equals(enteredOtp)) {
                        log.info("✅ {} OTP verified: {}", type, otpKey);
                        deleteOtp(otpKey);
                        resetAttempts(attemptsKey);
                        return OtpVerificationResult.success();
                    }

                    log.warn("❌ Invalid {} OTP: {}", type, otpKey);
                    incrementAttempts(attemptsKey, attemptsTtl);
                    int remaining = getRemainingAttempts(attemptsKey);
                    return OtpVerificationResult.invalid(remaining);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Void> invalidateSetupOtp(String userId) {
        String key = SETUP_OTP_KEY + userId;
        return Mono.fromRunnable(() -> {
                    redisTemplate.delete(key);
                    redisTemplate.delete(SETUP_ATTEMPTS_KEY + userId);
                    log.info("✅ Setup OTP invalidated for user: {}", userId);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    public Mono<Void> invalidateLoginOtp(String userId) {
        String key = LOGIN_OTP_KEY + userId;
        return Mono.fromRunnable(() -> {
                    redisTemplate.delete(key);
                    redisTemplate.delete(LOGIN_ATTEMPTS_KEY + userId);
                    log.info("✅ Login OTP invalidated for user: {}", userId);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    private void deleteOtp(String key) {
        redisTemplate.delete(key);
        log.debug("🗑️ OTP deleted: {}", key);
    }

    /* =========================
       Rate Limiting
       ========================= */

    private Mono<Boolean> checkRateLimit(String key, int maxRequests) {
        return Mono.fromCallable(() -> {
                    Object raw = redisTemplate.opsForValue().get(key);

                    if (raw == null) return true;

                    long count = ((Number) raw).longValue();
                    return count < maxRequests;
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> incrementRateLimit(String key) {
        return Mono.fromRunnable(() -> {
                    redisTemplate.opsForValue().increment(key);
                    redisTemplate.expire(
                            key,
                            Duration.ofMinutes(rateLimitMinutes).toMillis(),
                            TimeUnit.MILLISECONDS
                    );
                })
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /* =========================
       Attempt Tracking
       ========================= */

    private void incrementAttempts(String key, Duration ttl) {
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, ttl.toMillis(), TimeUnit.MILLISECONDS);
    }

    private boolean hasExceededAttempts(String key) {
        Object raw = redisTemplate.opsForValue().get(key);
        if (raw == null) return false;

        long attempts = ((Number) raw).longValue();
        return attempts >= maxAttempts;
    }

    private int getRemainingAttempts(String key) {
        Object raw = redisTemplate.opsForValue().get(key);
        long attempts = raw != null ? ((Number) raw).longValue() : 0L;

        long remaining = maxAttempts - attempts;
        return (int) Math.max(remaining, 0);
    }

    private void resetAttempts(String key) {
        redisTemplate.delete(key);
    }
}
