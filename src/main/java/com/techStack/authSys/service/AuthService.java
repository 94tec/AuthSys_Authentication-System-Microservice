package com.techStack.authSys.service;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.FieldValue;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteResult;
import com.google.firebase.auth.*;
import com.techStack.authSys.config.AppConfig;
import com.techStack.authSys.config.PermissionsConfig;
import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.event.UserRegisteredEvent;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.exception.EmailAlreadyExistsException;
import com.techStack.authSys.models.*;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.util.FirestoreUtil;
import jakarta.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

@Service
public  class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private static final String COLLECTION_USERS = "users";
    private static final String COLLECTION_REGISTRATION_METADATA = "registration_metadata";

    // Injected dependencies
    private final FirebaseAuth firebaseAuth;
    private final Firestore firestore;
    private final EmailServiceInstance1 emailServiceInstance1;
    private final JwtService jwtService;
    private final DomainValidationService domainValidationService;
    private final PasswordPolicyService passwordPolicyService;
    private final AuditLogService auditLogService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RegistrationThrottleService registrationThrottleService;
    private final GeoLocationService geoLocationService;
    private final SuspiciousActivityService suspiciousActivityService;
    private final ApplicationEventPublisher eventPublisher;
    private final DeviceVerificationService deviceVerificationService;
    private final EncryptionService encryptionService;
    private final AppConfig appConfig;
    private final RedisCacheService redisCacheService;
    private final MetricsService metricsService;

    // Password policy configuration
    @Value("${security.password.policy.min-length}")
    private int minPasswordLength;

    @Value("${security.password.policy.require-upper}")
    private boolean requireUpperCase;

    @Value("${security.password.policy.require-special}")
    private boolean requireSpecialChar;

    @Value("${security.password.policy.history-size}")
    private int passwordHistorySize;

    @Autowired
    public AuthService(
            FirebaseAuth firebaseAuth,
            Firestore firestore,
            EmailServiceInstance1 emailServiceInstance1,
            JwtService jwtService,
            DomainValidationService domainValidationService,
            PasswordPolicyService passwordPolicyService,
            AuditLogService auditLogService,
            FirebaseServiceAuth firebaseServiceAuth,
            RegistrationThrottleService registrationThrottleService,
            GeoLocationService geoLocationService,
            SuspiciousActivityService suspiciousActivityService,
            ApplicationEventPublisher eventPublisher,
            DeviceVerificationService deviceVerificationService,
            EncryptionService encryptionService,
            AppConfig appConfig,
            RedisCacheService redisCacheService,
            MetricsService metricsService
    ) {
        this.firebaseAuth = firebaseAuth;
        this.firestore = firestore;
        this.emailServiceInstance1 = emailServiceInstance1;
        this.jwtService = jwtService;
        this.domainValidationService = domainValidationService;
        this.passwordPolicyService = passwordPolicyService;
        this.auditLogService = auditLogService;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.registrationThrottleService = registrationThrottleService;
        this.geoLocationService = geoLocationService;
        this.suspiciousActivityService = suspiciousActivityService;
        this.eventPublisher = eventPublisher;
        this.deviceVerificationService = deviceVerificationService;
        this.encryptionService = encryptionService;
        this.appConfig = appConfig;
        this.redisCacheService = redisCacheService;
        this.metricsService = metricsService;
    }

    /**
     * Main registration entry point.
     *
     * @param userDto  incoming registration DTO
     * @param exchange server web exchange (for IP resolution and request metadata)
     * @return Mono<User> the created user
     */

    public Mono<User> registerUser(UserDTO userDto, ServerWebExchange exchange) {
        long startTime = System.currentTimeMillis();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(ipAddress, userDto.getUserAgent());

        logger.info("Registration attempt for email: {} from IP: {}", userDto.getEmail(), ipAddress);

        return Mono.just(userDto)
                // 1. Validate incoming DTO fields (non-null, email format, etc.)
                .flatMap(this::validateUserInput)

                // 2. Duplicate checks (Redis cache + Firestore)
                .flatMap(this::checkDuplicateEmail)

                // 3. Registration pattern checks: rate limit, geolocation, suspicious activity
                .flatMap(dto -> checkRegistrationPatterns(dto, ipAddress).thenReturn(dto))

                // 4. Domain & password policy validations
                .flatMap(dto -> domainValidationService.validateActiveDomain(dto).thenReturn(dto))
                .flatMap(dto -> passwordPolicyService.validatePassword(dto).thenReturn(dto))

                // 5. Honeypot check
                .flatMap(dto -> {
                    if (StringUtils.hasText(dto.getHoneypot())) {
                        return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Invalid form submission"));
                    }
                    return Mono.just(dto);
                })

                // 6. Create Firebase user
                .flatMap(dto -> firebaseServiceAuth.createFirebaseUser(dto, ipAddress, deviceFingerprint))

                // 7. Save device fingerprint and registration metadata
                .flatMap(user -> savePostRegistrationData(user, ipAddress, deviceFingerprint))

                // 8. Send verification email (safe - won't break registration on failure)
                .flatMap(user -> sendVerificationEmailSafe(user, ipAddress))

                // 9. ISSUES: audit, cache, metrics, and event publish
                .doOnSuccess(user -> {
                    long duration = System.currentTimeMillis() - startTime;
                    logger.info("Registration completed for {} in {} ms", user.getEmail(), duration);
                    eventPublisher.publishEvent(new UserRegisteredEvent(user, ipAddress));
                    auditAndMetrics(user, startTime, ipAddress, deviceFingerprint, duration);
                })

                // 10. Error handling
                .doOnError(e -> {
                    long duration = System.currentTimeMillis() - startTime;
                    logger.error("Registration failed for {} after {} ms: {}",
                            Objects.toString(userDto.getEmail(), "unknown"), duration, e.getMessage());
                    metricsService.incrementCounter("user.registration.failure");
                    // If the failure is because Firebase reported EMAIL_EXISTS we attempt cleanup
                    if (e instanceof FirebaseAuthException && "EMAIL_EXISTS".equals(((FirebaseAuthException) e).getErrorCode())) {
                        firebaseServiceAuth.cleanupFailedRegistration(userDto.getEmail())
                                .subscribe(); // one-off cleanup: issues; keep as last-resort
                    }
                })

                // 11. Retry policy for retriable errors (network, transient service issues)
                .retryWhen(Retry.backoff(3, Duration.ofMillis(200))
                        .filter(this::isRetryableError)
                        .doBeforeRetry(retrySignal ->
                                logger.info("Retrying registration attempt #{}", retrySignal.totalRetriesInARow() + 1)
                        )
                        .onRetryExhaustedThrow((retrySpec, retrySignal) -> {
                            logger.error("Registration service unavailable after max retries (3).");
                            return new CustomException(
                                    HttpStatus.SERVICE_UNAVAILABLE,
                                    "Registration service temporarily unavailable"
                            );
                        })
                );
    }

    public Mono<UserDTO> validateUserInput(UserDTO userDto) {
        return Mono.fromCallable(() -> {
            if (!StringUtils.hasText(userDto.getEmail())) {
                throw new ValidationException("Email is required");
            }
            if (!StringUtils.hasText(userDto.getPassword())) {
                throw new ValidationException("Password is required");
            }
            if (StringUtils.hasText(userDto.getHoneypot())) {
                throw new ValidationException("Invalid form submission");
            }
            return userDto;
        });
    }

    /**
     * Check for duplicate email using Redis cache first then Firestore.
     */
    private Mono<UserDTO> checkDuplicateEmail(UserDTO userDto) {
        return redisCacheService.isEmailRegistered(userDto.getEmail())
                .onErrorResume(e -> {
                    logger.warn("Redis lookup failed for {}: {} - continuing to Firestore check", userDto.getEmail(), e.getMessage());
                    return Mono.just(false);
                })
                .flatMap(inCache -> {
                    if (Boolean.TRUE.equals(inCache)) {
                        logger.warn("Duplicate email found in Redis: {}", userDto.getEmail());
                        return Mono.error(new EmailAlreadyExistsException());
                        //return Mono.error(new EmailAlreadyExistsException(userDto.getEmail()));
                    }
                    return checkFirestoreForEmail(userDto);
                });
    }

    private Mono<UserDTO> checkFirestoreForEmail(UserDTO userDto) {
        return firebaseServiceAuth.findByEmail(userDto.getEmail())
                .flatMap(foundUser -> {
                    logger.warn("Duplicate email found in Firestore: {}", userDto.getEmail());
                    return Mono.<UserDTO>error(new EmailAlreadyExistsException());
                    //return Mono.<UserDTO>error(new EmailAlreadyExistsException(userDto.getEmail()));
                })
                .switchIfEmpty(Mono.just(userDto));
    }

    /**
     * Save device fingerprint, persist user metadata and cache the registered email.
     */
    private Mono<User> savePostRegistrationData(User user, String ipAddress, String deviceFingerprint) {
        // Save fingerprint and user details in sequence
        return deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint)
                .then(firebaseServiceAuth.saveUser(user, ipAddress, deviceFingerprint))
                .then(saveRegistrationMetadata(user, ipAddress))
                .then(Mono.fromRunnable(() -> {
                    // cache registered email - non-blocking side effect
                    try {
                        redisCacheService.cacheRegisteredEmail(user.getEmail()).subscribe();
                    } catch (Exception ex) {
                        logger.warn("Failed to cache registered email for {}: {}", user.getEmail(), ex.getMessage());
                    }
                }))
                .thenReturn(user);
    }

    /**
     * Attempt to send verification email but swallow failures (log + audit) so registration can proceed.
     */
    private Mono<User> sendVerificationEmailSafe(User user, String ipAddress) {
        return sendVerificationEmail(user, ipAddress)
                .onErrorResume(e -> {
                    logger.warn("Verification email process failed for {}: {}", user.getEmail(), e.getMessage());
                    logger.debug("Full error details:", e); // Add debug logging for full stack trace
                    auditLogService.logAudit(user, ActionType.EMAIL_FAILURE,
                            "Verification email failed", e.getMessage());

                    // Return user to allow registration to proceed
                    return Mono.just(user);
                })
                .doOnSuccess(u -> logger.info("Verification email process completed for user: {}", u.getEmail()));
    }

    private Mono<User> sendVerificationEmail(User user, String ipAddress) {
        return jwtService.generateEmailVerificationToken(user.getId(), user.getEmail(), ipAddress)
                .flatMap(token -> {
                    String hashedToken = encryptionService.hashToken(token);

                    // Build verification link
                    String verificationLink = String.format("%s/api/auth/verify-email?token=%s",
                            appConfig.getBaseUrl(), token);

                    // Send email asynchronously (fire and forget)
                    emailServiceInstance1.sendVerificationEmail(user.getEmail(), verificationLink)
                            .doOnSuccess(__ -> logger.info("✅ Sent verification email to {}", user.getEmail()))
                            .doOnError(e -> logger.error("❌ Failed to send verification email to {}: {}", user.getEmail(), e.getMessage()))
                            .subscribe();

                    // Prepare Firestore update data
                    Map<String, Object> updateData = new HashMap<>();
                    updateData.put("verificationTokenHash", hashedToken);
                    updateData.put("verificationTokenExpiresAt", Instant.now().plus(Duration.ofHours(24)));

                    DocumentReference userDoc = firestore.collection(COLLECTION_USERS).document(user.getId());

                    // Firestore transaction wrapped in a reactive Mono
                    return Mono.fromFuture(() ->
                                    FirestoreUtil.toCompletableFuture(
                                            firestore.runTransaction(transaction -> {
                                                transaction.update(userDoc, updateData);
                                                return null;
                                            })
                                    )
                            )
                            .doOnSuccess(__ -> logger.info("✅ Stored verification token for {}", user.getEmail()))
                            .thenReturn(user);
                })
                .onErrorResume(e -> {
                    logger.warn("⚠️ Failed to send verification email for {}: {}", user.getEmail(), e.getMessage());
                    return Mono.just(user); // don’t block registration on email failure
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private static class EmailVerificationData {
        final String token;
        final String hashedToken;
        final String verificationLink;

        EmailVerificationData(String token, String hashedToken, String verificationLink) {
            this.token = token;
            this.hashedToken = hashedToken;
            this.verificationLink = verificationLink;
        }
    }

    public Mono<Void> checkRegistrationPatterns(UserDTO userDto, String ipAddress) {
        return registrationThrottleService.checkRateLimit(ipAddress)
                .doOnSuccess(v -> logger.info("Rate limit check passed for IP: {}", ipAddress))
                .doOnError(e -> logger.error("Rate limit check failed for IP: {}", ipAddress, e))

                .then(geoLocationService.validateLocation(ipAddress))
                .doOnSuccess(v -> logger.info("Geolocation validation passed for IP: {}", ipAddress))
                .doOnError(e -> logger.error("Geolocation validation failed for IP: {}", ipAddress, e))

                .then(suspiciousActivityService.checkPatterns(
                        userDto.getEmail(),
                        ipAddress,
                        userDto.getRegistrationMetadata()
                ))
                .doOnSuccess(v -> logger.info("Suspicious activity check passed for user: {}", userDto.getEmail()))
                .doOnError(e -> logger.error("Suspicious activity check failed for user: {}", userDto.getEmail(), e))

                .onErrorResume(e -> {
                    logger.warn("Error during registration pattern checks for user: {}. Proceeding with caution.",
                            userDto.getEmail(), e);
                    return Mono.empty();  // Allows the flow to continue even if a check fails
                });
    }
    public Mono<Void> saveRegistrationMetadata(User user, String ipAddress) {
        if (user == null || user.getId() == null || ipAddress == null || ipAddress.isBlank()) {
            logger.warn("Invalid input: User or IP address is null/empty");
            return Mono.error(new IllegalArgumentException("User or IP address cannot be null/empty"));
        }

        UserDTO.RegistrationMetadata metadata = new UserDTO.RegistrationMetadata(
                user.getId(),
                ipAddress,
                Instant.now(),
                user.getDeviceFingerprint()
        );

        // Convert ApiFuture to CompletableFuture
        ApiFuture<DocumentReference> apiFuture = firestore.collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_REGISTRATION_METADATA)
                .add(metadata);

        CompletableFuture<DocumentReference> completableFuture = FirestoreUtil.toCompletableFuture(apiFuture);

        return Mono.fromFuture(completableFuture)
                .doOnSuccess(v -> logger.info("Successfully saved registration metadata for user ID: {}", user.getId()))
                .doOnError(e -> logger.error("Failed to save registration metadata for user ID: {}", user.getId(), e))
                .onErrorResume(e -> {
                    if (e instanceof ExecutionException) {
                        logger.error("Firestore execution error: {}", e.getMessage());
                    } else {
                        logger.error("Unexpected error while saving registration metadata: {}", e.getMessage());
                    }
                    return Mono.empty(); // Prevents breaking the flow in case of failure
                })
                .then();
    }
    /**
     * Centralized audit and metric reporting
     */
    private void auditAndMetrics(User user, long startTime, String ipAddress, String deviceFingerprint, long durationMs) {
        // Audit
        auditLogService.logAudit(user, ActionType.REGISTRATION,
                String.format("User registered. DeviceFingerprint: %s", deviceFingerprint),
                ipAddress);

        // Cache the email safely (best-effort)
        try {
            redisCacheService.cacheRegisteredEmail(user.getEmail()).subscribe();
        } catch (Exception e) {
            logger.warn("Failed to cache registered email for {}: {}", user.getEmail(), e.getMessage());
        }

        // Metrics
        metricsService.incrementCounter("user.registration.success");
        metricsService.recordTimer("user.registration.time", Duration.ofMillis(durationMs));

        // Publish domain event for other systems to consume
        try {
            eventPublisher.publishEvent(new UserRegisteredEvent(user, ipAddress));
        } catch (Exception e) {
            logger.warn("Failed to publish UserRegisteredEvent for {}: {}", user.getEmail(), e.getMessage());
        }
    }

    public boolean isRetryableError(Throwable throwable) {
        boolean retryable = false;

        if (throwable instanceof CustomException custom) {
            retryable = custom.getStatusCode().is5xxServerError();
        } else if (throwable instanceof TimeoutException ||
                throwable instanceof java.net.ConnectException ||
                throwable instanceof java.net.SocketTimeoutException ||
                throwable instanceof org.springframework.web.reactive.function.client.WebClientRequestException) {
            retryable = true;
        } else if (throwable instanceof FirebaseAuthException fae) {
            String errorCode = String.valueOf(fae.getErrorCode());
            int status = fae.getHttpResponse() != null ? fae.getHttpResponse().getStatusCode() : -1;
            retryable = (status >= 500) ||
                    "INTERNAL_ERROR".equalsIgnoreCase(errorCode) ||
                    "UNAVAILABLE".equalsIgnoreCase(errorCode) ||
                    "UNKNOWN".equalsIgnoreCase(errorCode);
        }

        logger.debug("Retry check for {} → {}", throwable.getClass().getSimpleName(), retryable);
        return retryable;
    }

    public Mono<Void> verifyEmail(String token, String ipAddress) {
        return jwtService.verifyEmailVerificationToken(token)
                .flatMap(claims ->
                        validateIpAddress(claims, ipAddress)
                                .then(updateUserVerificationStatus(claims.userId()))
                                .then(logSuccessfulVerification(claims, ipAddress))
                )
                .doOnSuccess(__ -> logger.info("Email verification completed successfully"))
                .doOnError(e -> {
                    if (e instanceof CustomException) {
                        CustomException ce = (CustomException) e;
                        logger.warn("Email verification failed for IP {}: {} {}",
                                ipAddress, ce.getStatus().value(), ce.getMessage());
                    } else {
                        logger.error("Email verification failed for IP {}: {}", ipAddress, e.getMessage(), e);
                        // Wrap unexpected errors as 500
                        throw new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Token processing failed");
                    }
                });
    }

    private Mono<Void> validateIpAddress(TokenClaims claims, String ipAddress) {
        if (!claims.ipAddress().equals(ipAddress)) {
            return logFailedAttempt(claims, ipAddress); // Log but continue processing
        }
        return Mono.empty();
    }

    private Mono<Void> updateUserVerificationStatus(String userId) {
        return updateFirebaseUser(userId)
                .then(updateFirestoreUser(userId));
    }

    private Mono<Void> updateFirebaseUser(String userId) {
        return Mono.fromCallable(() -> {
            firebaseAuth.updateUser(
                    new UserRecord.UpdateRequest(userId)
                            .setEmailVerified(true)
            );
            return null;
        });
    }

    private Mono<Void> updateFirestoreUser(String userId) {
        ApiFuture<WriteResult> future = firestore.collection(COLLECTION_USERS).document(userId)
                .update(
                        "emailVerified", true,
                        "enabled", true,
                        "verificationToken", FieldValue.delete()
                );

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future)).then();
    }
    private Mono<Void> logSuccessfulVerification(TokenClaims claims, String ipAddress) {
        return Mono.fromRunnable(() -> auditLogService.logAudit(
                buildUser(claims),
                ActionType.EMAIL_VERIFICATION,
                "Email verified successfully",
                ipAddress
        ));
    }

    private Mono<Void> logFailedAttempt(TokenClaims claims, String ipAddress) {
        return Mono.fromRunnable(() -> auditLogService.logAudit(
                buildUser(claims),
                ActionType.EMAIL_VERIFICATION,
                "Attempt to verify email from different IP",
                ipAddress
        ));
    }

    private User buildUser(TokenClaims claims) {
        return User.builder()
                .id(claims.userId())
                .email(claims.email())
                .build();
    }

}

