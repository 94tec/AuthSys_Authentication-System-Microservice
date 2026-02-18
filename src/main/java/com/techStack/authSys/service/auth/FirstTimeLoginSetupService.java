package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.request.ChangePasswordRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.request.VerifyOtpRequest;
import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.notification.EmailService;
import com.techStack.authSys.repository.security.RateLimiterService;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.OtpService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.service.user.PasswordPolicyService;
import com.techStack.authSys.util.auth.TokenValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static com.techStack.authSys.models.audit.ActionType.FIRST_TIME_SETUP;

/**
 * First-Time Login Setup Service - PRODUCTION READY
 *
 * ✅ FIXED: Using correct getter methods like LoginOtpService
 * ✅ FIXED: Using JwtService patterns for token validation
 * ✅ FIXED: Proper reactive error handling
 *
 * FLOW:
 * =====
 * 0. User logs in with temp password
 *    → Returns temporaryToken + firstTimeLogin=true
 *
 * 1. POST /change-password (Step 1)
 *    ↓
 *    - Validate temp token
 *    - Validate password (complexity, strength) ✅
 *    - Hash password
 *    - STAGE in Redis (NOT in database yet!) ⭐
 *    - Lock temp password
 *    - Send OTP via SMS + Email
 *    - Return: "Password staged, OTP sent"
 *
 * 2. POST /verify-otp (Step 2)
 *    ↓
 *    - Verify OTP
 *    - Generate verificationToken (5-min)
 *    - Return: verificationToken
 *    - User: "OTP confirmed! ✅"
 *
 * 3. POST /complete (Step 3) - Uses verificationToken
 *    ↓
 *    - Validate verificationToken
 *    - Retrieve staged password from Redis
 *    - COMMIT to database (FIRST TIME IN DB!) ⭐
 *    - Activate account
 *    - Invalidate all sessions
 *    - Clean up Redis
 *    - Generate new tokens
 *    - Return: TokenPair
 *
 * @author TechStack Team
 * @version 5.1 - Fixed Production
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FirstTimeLoginSetupService {

    private final JwtService jwtService;
    private final OtpService otpService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final SessionService sessionManagementService;
    private final EmailService emailService;
    private final RateLimiterService rateLimiterService;
    private final AuditLogService auditLogService;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final PasswordPolicyService passwordPolicyService;
    private final TokenValidator tokenValidator;

    // Redis key prefixes
    private static final String TEMP_PASSWORD_LOCK_PREFIX = "ftl:lock:";
    private static final String STAGED_PASSWORD_PREFIX = "ftl:staged:";
    private static final String VERIFICATION_TOKEN_PREFIX = "ftl:verify:";

    // Expiry durations
    private static final Duration STAGED_PASSWORD_EXPIRY = Duration.ofMinutes(15);
    private static final Duration VERIFICATION_TOKEN_EXPIRY = Duration.ofMinutes(5);
    private static final Duration TEMP_LOCK_EXPIRY = Duration.ofMinutes(15);

    /* =========================
       STEP 1: Change Password + Send OTP
       ========================= */

    /**
     * STEP 1: Validate password, STAGE in Redis, send OTP
     *
     * ⭐ KEY: Password is VALIDATED and STAGED, but NOT saved to DB
     *
     * Flow:
     * 1. Validate temp token
     * 2. Verify user in first-time setup state
     * 3. Validate password (complexity, strength, history)
     * 4. Hash password
     * 5. STAGE hashed password in Redis (15-min expiry)
     * 6. Lock temp password in Redis
     * 7. Send OTP via SMS + Email
     * 8. Return success
     *
     * @param tempToken Temporary token from login
     * @param request Contains new password
     * @return OtpResult with delivery status
     */
    /**
     * Step 1: Change password first time - Generate and send OTP
     *
     * Flow:
     * 1. Validate temporary token
     * 2. Verify user requires first-time setup
     * 3. ✅ Validate password using UserRegistrationDTO
     * 4. Check rate limits
     * 5. Stage password in Redis (NOT in DB!)
     * 6. Lock temporary password
     * 7. Generate and send OTP
     * 8. Return OtpResult (HTTP 200 - password still not in DB!)
     *
     * @param tempToken Temporary token from login
     * @param request Contains new password
     * @return OtpResult with OTP delivery status
     */
    public Mono<OtpResult> changePasswordFirstTime(
            String tempToken,
            ChangePasswordRequest request) {

        Instant startTime = clock.instant();

        log.info("🚀 [STEP 1/3] Password change + OTP at {}", startTime);

        return tokenValidator.validateTemporaryToken(tempToken)  // Using TokenValidator
                .flatMap(firebaseServiceAuth::getUserById)
                .flatMap(user -> {
                    if (!user.isForcePasswordChange()) {
                        log.warn("⚠️ User {} NOT in first-time setup state", user.getId());
                        return Mono.error(new IllegalStateException(
                                "User is not in first-time setup state"));
                    }

                    return isSetupInProgress(user.getId())
                            .flatMap(inProgress -> {
                                if (inProgress) {
                                    return Mono.error(new IllegalStateException(
                                            "Setup already in progress. Complete OTP verification or restart."));
                                }
                                return Mono.just(user);
                            });
                })
                .flatMap(user -> {
                    log.info("🔍 [STEP 1/3] Validating password for user {}", user.getId());

                    UserRegistrationDTO validationDto = UserRegistrationDTO.builder()
                            .password(request.newPassword())
                            .uid(user.getId())
                            .build();

                    return passwordPolicyService.validatePassword(validationDto)
                            .then(Mono.just(user));
                })
                .flatMap(user -> {
                    return rateLimiterService.checkOtpRateLimit(user.getId(), "SETUP")
                            .then(Mono.just(user));
                })
                .flatMap(user -> {
                    String hashedPassword = passwordEncoder.encode(request.newPassword());

                    log.info("💾 [STEP 1/3] STAGING password for user {} (NOT in DB yet)",
                            user.getId());

                    return stagePasswordInRedis(user.getId(), hashedPassword)
                            .then(Mono.just(user));
                })
                .flatMap(user -> {
                    log.warn("🔒 [STEP 1/3] LOCKING temp password for user {}", user.getId());

                    return lockTempPasswordInRedis(user.getId())
                            .then(Mono.just(user));
                })
                .flatMap(user -> {
                    log.info("📱 [STEP 1/3] Sending OTP to user {}", user.getId());

                    return otpService.generateAndSendSetupOtp(user.getId(), user.getPhoneNumber())
                            .flatMap(otpResult -> {
                                boolean otpSent = otpResult.isSent() && !otpResult.isRateLimited();

                                return sendOtpEmailNotification(user, otpResult)
                                        .map(emailSent -> {
                                            auditPasswordStaged(user.getId(), otpSent, emailSent);
                                            return otpResult;
                                        });
                            });
                })
                .doOnSuccess(result -> {
                    Duration duration = Duration.between(startTime, clock.instant());
                    log.info("✅ [STEP 1/3] Password STAGED + OTP sent in {} - Password NOT in DB yet!",
                            duration);
                })
                .doOnError(e -> {
                    Duration duration = Duration.between(startTime, clock.instant());
                    log.error("❌ [STEP 1/3] Failed after {}: {}", duration, e.getMessage());
                });
    }

    /**
     * Stage password in Redis (encrypted, 15-min expiry)
     */
    private Mono<Void> stagePasswordInRedis(String userId, String hashedPassword) {
        String key = STAGED_PASSWORD_PREFIX + userId;

        return redisTemplate.opsForValue()
                .set(key, hashedPassword, STAGED_PASSWORD_EXPIRY)
                .flatMap(success -> {
                    if (!success) {
                        return Mono.error(new RuntimeException("Failed to stage password"));
                    }
                    log.info("✅ Password STAGED in Redis for user {} (expires in 15 min)", userId);
                    return Mono.empty();
                });
    }

    /**
     * Lock temp password in Redis
     */
    private Mono<Void> lockTempPasswordInRedis(String userId) {
        String key = TEMP_PASSWORD_LOCK_PREFIX + userId;

        return redisTemplate.opsForValue()
                .set(key, "LOCKED", TEMP_LOCK_EXPIRY)
                .flatMap(success -> {
                    if (!success) {
                        return Mono.error(new RuntimeException("Failed to lock temp password"));
                    }
                    log.info("✅ Temp password LOCKED in Redis for user {}", userId);
                    return Mono.empty();
                });
    }

    /**
     * Check if setup in progress
     */
    private Mono<Boolean> isSetupInProgress(String userId) {
        String key = TEMP_PASSWORD_LOCK_PREFIX + userId;
        return redisTemplate.hasKey(key);
    }

    /**
     * Send OTP email notification
     */
    private Mono<Boolean> sendOtpEmailNotification(User user, OtpResult otpResult) {
        // ✅ FIXED: Use isSent() like LoginOtpService
        if (!otpResult.isSent()) return Mono.just(false);

        return emailService.sendOtpNotification(
                        user.getEmail(),
                        user.getFirstName() + " " + user.getLastName(),
                        "Complete your first-time setup with OTP",
                        clock.instant()
                )
                .thenReturn(true)
                .onErrorReturn(false);
    }

    /* =========================
       STEP 2: Verify OTP
       ========================= */

    /**
     * STEP 2: Verify OTP and issue verification token
     *
     * Flow:
     * 1. Validate temp token
     * 2. Verify setup in progress
     * 3. Verify OTP
     * 4. Generate verification token (5-min)
     * 5. Return verification token
     *
     * @param tempToken Temp token from login
     * @param request Contains OTP
     * @return OtpVerificationResult with verification token
     */
    public Mono<OtpVerificationResult> verifyOtpAndCompleteSetup(
            String tempToken,
            VerifyOtpRequest request) {

        Instant startTime = clock.instant();

        log.info("🔍 [STEP 2/3] Verifying OTP at {}", startTime);

        return tokenValidator.validateTemporaryToken(tempToken)  // Using TokenValidator
                .flatMap(firebaseServiceAuth::getUserById)
                .flatMap(user -> {
                    return isSetupInProgress(user.getId())
                            .flatMap(inProgress -> {
                                if (!inProgress) {
                                    return Mono.error(new IllegalStateException(
                                            "Setup not initiated. Please start from Step 1."));
                                }
                                return Mono.just(user);
                            });
                })
                .flatMap(user -> {
                    return otpService.verifySetupOtp(user.getId(), request.otp())
                            .flatMap(otpResult -> {
                                if (!otpResult.isValid()) {
                                    log.warn("⚠️ [STEP 2/3] OTP invalid for user {}: {}",
                                            user.getId(), otpResult.getMessage());

                                    return Mono.just(OtpVerificationResult.builder()
                                            .valid(false)
                                            .expired(otpResult.isExpired())
                                            .attemptsExceeded(otpResult.isAttemptsExceeded())
                                            .remainingAttempts(otpResult.getRemainingAttempts())
                                            .message(otpResult.getMessage())
                                            .build());
                                }

                                log.info("✅ [STEP 2/3] OTP verified for user {}", user.getId());

                                return generateVerificationToken(user.getId())
                                        .map(verificationToken -> {
                                            auditOtpVerified(user.getId());

                                            return OtpVerificationResult.builder()
                                                    .valid(true)
                                                    .message("OTP verified! Proceeding to activate account...")
                                                    .verificationToken(verificationToken)
                                                    .expiresInSeconds(VERIFICATION_TOKEN_EXPIRY.toSeconds())
                                                    .build();
                                        });
                            });
                })
                .doOnSuccess(result -> {
                    Duration duration = Duration.between(startTime, clock.instant());
                    if (result.isValid()) {
                        log.info("✅ [STEP 2/3] OTP verified in {} - Proceeding to Step 3", duration);
                    }
                })
                .doOnError(e -> {
                    Duration duration = Duration.between(startTime, clock.instant());
                    log.error("❌ [STEP 2/3] Failed after {}: {}", duration, e.getMessage());
                });
    }

    /**
     * Generate verification token (5-min, single-use)
     */
    private Mono<String> generateVerificationToken(String userId) {
        String token = "vfy_" + UUID.randomUUID().toString();
        String key = VERIFICATION_TOKEN_PREFIX + token;

        return redisTemplate.opsForValue()
                .set(key, userId, VERIFICATION_TOKEN_EXPIRY)
                .map(success -> {
                    if (!success) {
                        throw new RuntimeException("Failed to store verification token");
                    }
                    log.info("✅ Verification token generated (expires in 5 min)");
                    return token;
                });
    }

    /* =========================
       STEP 3: Complete Setup (COMMIT to DB)
       ========================= */

    /**
     * STEP 3: COMMIT password to database and activate account
     *
     * ⭐ THIS IS WHERE PASSWORD IS FINALLY SAVED TO DATABASE
     *
     * Flow:
     * 1. Validate verification token (consume it)
     * 2. Retrieve staged password from Redis
     * 3. COMMIT to database (FIRST TIME IN DB!) ⭐
     * 4. Activate account (forcePasswordChange=false, phoneVerified=true)
     * 5. Invalidate all sessions
     * 6. Clean up Redis keys
     * 7. Send confirmation email
     * 8. Generate new tokens
     *
     * @param verificationToken Token from Step 2
     * @return TokenPair for user
     */
    public Mono<TokenPair> completeSetup(String verificationToken) {
        Instant startTime = clock.instant();

        log.info("🎯 [STEP 3/3] Completing setup - COMMITTING password to DB at {}", startTime);

        return validateAndConsumeVerificationToken(verificationToken)
                .flatMap(userId ->
                        Mono.zip(
                                firebaseServiceAuth.getUserById(userId),
                                getStagedPassword(userId)
                        )
                )
                .flatMap(tuple -> {
                    User user = tuple.getT1();
                    String stagedHashedPassword = tuple.getT2();

                    if (stagedHashedPassword == null) {
                        return Mono.error(new IllegalStateException(
                                "No staged password found. Please restart from Step 1."));
                    }

                    log.info("💾 [STEP 3/3] COMMITTING password to database for user {}",
                            user.getId());

                    user.setPassword(stagedHashedPassword);
                    user.setForcePasswordChange(false);
                    user.setPhoneVerified(true);
                    user.setFirstTimeSetupCompleted(true);
                    user.setFirstTimeSetupCompletedAt(clock.instant());
                    user.setPasswordLastChanged(clock.instant());

                    return firebaseServiceAuth.save(user)
                            .thenReturn(user);
                })
                .flatMap(user -> {
                    log.warn("🔒 [STEP 3/3] Invalidating all sessions for user {}", user.getId());

                    return sessionManagementService.invalidateAllSessionsForUser(user.getId())
                            .then(Mono.just(user))
                            .onErrorResume(e -> {
                                log.error("Failed to invalidate sessions: {}", e.getMessage());
                                return Mono.just(user);
                            });
                })
                .flatMap(user -> {
                    return cleanupRedisKeys(user.getId())
                            .thenReturn(user);
                })
                .flatMap(user -> {
                    return sendSetupCompletedEmail(user)
                            .thenReturn(user);
                })
                .map(user -> {
                    String accessToken = jwtService.generateAccessToken(user);
                    String refreshToken = jwtService.generateRefreshToken(user.getId());

                    Duration duration = Duration.between(startTime, clock.instant());

                    log.info("🎉 [STEP 3/3] Setup COMPLETED - Password in DB, account active! Duration: {}",
                            duration);

                    auditSetupCompleted(user.getId(), true, duration);

                    return new TokenPair(accessToken, refreshToken);
                })
                .doOnError(e -> {
                    Duration duration = Duration.between(startTime, clock.instant());
                    log.error("❌ [STEP 3/3] Failed after {}: {}", duration, e.getMessage());
                });
    }

    /**
     * Get staged password from Redis
     */
    private Mono<String> getStagedPassword(String userId) {
        String key = STAGED_PASSWORD_PREFIX + userId;
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * Validate and consume verification token (single-use)
     */
    private Mono<String> validateAndConsumeVerificationToken(String token) {
        if (token == null || token.isBlank()) {
            return Mono.error(new AuthException(
                    "Verification token required",
                    HttpStatus.BAD_REQUEST
            ));
        }

        String key = VERIFICATION_TOKEN_PREFIX + token;

        return redisTemplate.opsForValue()
                .get(key)
                .switchIfEmpty(Mono.error(new AuthException(
                        "Invalid or expired verification token",
                        HttpStatus.UNAUTHORIZED
                )))
                .flatMap(userId ->
                        redisTemplate.delete(key)
                                .thenReturn(userId)
                );
    }

    /**
     * Clean up Redis keys
     */
    private Mono<Void> cleanupRedisKeys(String userId) {
        return Mono.when(
                redisTemplate.delete(TEMP_PASSWORD_LOCK_PREFIX + userId),
                redisTemplate.delete(STAGED_PASSWORD_PREFIX + userId)
        );
    }

    /**
     * Send completion email
     */
    private Mono<Void> sendSetupCompletedEmail(User user) {
        return emailService.sendPasswordChangedNotification(
                        user.getEmail(),
                        user.getFirstName() + " " + user.getLastName(),
                        clock.instant()
                )
                .then()
                .onErrorResume(e -> {
                    log.error("Failed to send email: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    /* =========================
       Resend OTP
       ========================= */

    public Mono<OtpResult> resendOtp(String tempToken) {
        Instant now = clock.instant();

        log.info("🔄 Resending OTP at {}", now);

        return tokenValidator.validateTemporaryToken(tempToken)
                .flatMap(userId -> firebaseServiceAuth.getUserById(userId))
                .flatMap(user -> {
                    return isSetupInProgress(user.getId())
                            .flatMap(inProgress -> {
                                if (!inProgress) {
                                    return Mono.error(new IllegalStateException(
                                            "Setup not initiated."));
                                }
                                return Mono.just(user);
                            });
                })
                .flatMap(user ->
                        rateLimiterService.checkOtpRateLimit(user.getId(), "SETUP")
                                .then(Mono.just(user))
                )
                .flatMap(user ->
                        otpService.invalidateSetupOtp(user.getId())
                                .then(Mono.just(user))
                                .onErrorResume(e -> Mono.just(user))
                )
                .flatMap(user ->
                        otpService.generateAndSendSetupOtp(user.getId(), user.getPhoneNumber())
                )
                .doOnSuccess(result -> log.info("✅ OTP resent"))
                .doOnError(e -> log.error("❌ Resend failed: {}", e.getMessage()));
    }

    /* =========================
       Token Validation
       ========================= */

    /* =========================
       Audit Logging
       ========================= */

    private void auditPasswordStaged(String userId, boolean otpSent, boolean emailSent) {
        auditLogService.logAuditEvent(
                userId,
                FIRST_TIME_SETUP,
                "Step 1: Password staged + OTP sent",
                Map.of("step", 1, "passwordInDB", false, "passwordStaged", true,
                        "otpSent", otpSent, "emailSent", emailSent)
        ).subscribe();
    }

    private void auditOtpVerified(String userId) {
        auditLogService.logAuditEvent(
                userId,
                FIRST_TIME_SETUP,
                "Step 2: OTP verified",
                Map.of("step", 2)
        ).subscribe();
    }

    private void auditSetupCompleted(String userId, boolean success, Duration duration) {
        auditLogService.logAuditEvent(
                userId,
                FIRST_TIME_SETUP,
                "Step 3: Setup completed - Password in DB",
                Map.of("step", 3, "success", success, "duration", duration.toString(),
                        "passwordInDB", true, "accountActivated", true)
        ).subscribe();
    }
}