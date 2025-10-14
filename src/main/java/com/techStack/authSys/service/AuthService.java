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
    public Mono<User> registerUser(UserDTO userDto, ServerWebExchange exchange) {
        return Mono.defer(() -> {
            logger.info("Registration attempt for email: {} from IP: {}", userDto.getEmail(), exchange.getRequest().getRemoteAddress());
            long startTime = System.currentTimeMillis();
            String ipAddress = deviceVerificationService.extractClientIp(exchange);
            String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(ipAddress, userDto.getUserAgent());

            return validateUserInput(userDto)
                    .flatMap(dto ->
                            redisCacheService.isEmailRegistered(dto.getEmail())
                                    .flatMap(isRegistered -> {
                                        if (Boolean.TRUE.equals(isRegistered)) {
                                            logger.warn("Duplicate registration attempt for email: {}", dto.getEmail());
                                            return Mono.error(new EmailAlreadyExistsException());
                                        }

                                        return firebaseServiceAuth.checkEmailAvailability(dto.getEmail())
                                                .flatMap(existsInFirestore -> {
                                                    if (Boolean.TRUE.equals(existsInFirestore)) {
                                                        logger.warn("Email already exists in Firestore: {}", dto.getEmail());
                                                        return Mono.error(new EmailAlreadyExistsException());
                                                    }
                                                    return checkRegistrationPatterns(dto, ipAddress).thenReturn(dto);
                                                });
                                    })
                    )
                    .flatMap(dto -> domainValidationService.validateActiveDomain(dto).thenReturn(dto))
                    .flatMap(dto -> passwordPolicyService.validatePassword(dto).thenReturn(dto))
                    .flatMap(dto -> {
                        if (StringUtils.hasText(dto.getHoneypot())) {
                            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Invalid form submission"));
                        }
                        return firebaseServiceAuth.createFirebaseUser(dto, ipAddress, deviceFingerprint);

                    })
                    .flatMap(user -> {
                        user.setDeviceFingerprint(deviceFingerprint);
                        return deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint)
                                .then(saveRegistrationMetadata(user, ipAddress))
                                .then(sendVerificationEmail(user, ipAddress)
                                        .timeout(Duration.ofSeconds(30))
                                        .onErrorResume(e -> {
                                            logger.warn("Email sending failed, proceeding with user creation", e);
                                            return Mono.just(user);
                                        }))
                                .thenReturn(user);
                    })
                    .doOnSuccess(user -> {
                        long duration = System.currentTimeMillis() - startTime;
                        logger.info("Registration completed for {} in {} ms", user.getEmail(), duration);
                        auditLogService.logAudit(
                                user,
                                ActionType.REGISTRATION,
                                STR."User registered successfully. Device: \{user.getDeviceFingerprint()}",
                                ipAddress
                        );
                        redisCacheService.cacheRegisteredEmail(user.getEmail());
                        eventPublisher.publishEvent(new UserRegisteredEvent(user, ipAddress));
                        metricsService.incrementCounter("user.registration.success");
                        metricsService.recordTimer("user.registration.time", Duration.ofMillis(duration));
                    })
                    .doOnError(e -> {
                        long duration = System.currentTimeMillis() - startTime;
                        logger.error("Registration failed for {} after {} ms: {}", userDto.getEmail(), duration, e.getMessage());
                        metricsService.incrementCounter("user.registration.failure");

                        if (e instanceof FirebaseAuthException && "EMAIL_EXISTS".equals(((FirebaseAuthException) e).getErrorCode())) {
                            firebaseServiceAuth.cleanupFailedRegistration(userDto.getEmail()).subscribe();
                        }
                    })
                    .name("userRegistration")
                    .doOnEach(signal -> {
                        if (signal.hasError()) {
                            logger.error("Error during user registration: {}", signal.getThrowable().getMessage());
                        } else if (signal.hasValue()) {
                            logger.info("User registration completed successfully");
                        }
                    })
                    .retryWhen(Retry.backoff(3, Duration.ofMillis(100))
                            .filter(this::isRetryableError)
                            .doBeforeRetry(retry -> logger.info("Retrying registration attempt #{}", retry.totalRetries() + 1))
                            .onRetryExhaustedThrow((spec, signal) -> {
                                logger.error("Registration service unavailable after retries");
                                return new CustomException(HttpStatus.SERVICE_UNAVAILABLE, "Registration service temporarily unavailable");
                            }));
        });
    }

    public Mono<UserDTO> validateUserInput(UserDTO userDto) {
        return Mono.fromCallable(() -> {
            // Basic validation
            if (userDto.getEmail() == null || userDto.getEmail().isEmpty()) {
                throw new CustomException(HttpStatus.BAD_REQUEST, "Email is required");
            }

            // Additional validation checks
            if (userDto.getPassword() == null || userDto.getPassword().isEmpty()) {
                throw new CustomException(HttpStatus.BAD_REQUEST, "Password is required");
            }

            return userDto;
        });
    }

    private Mono<User> sendVerificationEmail(User user, String ipAddress) {
        return Mono.fromCallable(() -> {
            // Generate email verification token
            String token = String.valueOf(jwtService.generateEmailVerificationToken(user.getId(), user.getEmail(), ipAddress));
            String hashedToken = encryptionService.hashToken(token); // Hash token before storing

            // Create verification link using environment-configured base URL
            String verificationLink = String.format("%s/api/auth/verify-email?token=%s",
                    appConfig.getBaseUrl(), token);

            // Send email asynchronously
            emailServiceInstance1.sendVerificationEmail(user.getEmail(), verificationLink);

            // Store hashed token and expiration timestamp in Firestore
            Map<String, Object> updateData = new HashMap<>();
            updateData.put("verificationTokenHash", hashedToken);
            updateData.put("verificationTokenExpiresAt", Instant.now().plus(Duration.ofHours(24))); // 24-hour expiry

            // Use a Firestore transaction to ensure atomicity
            firestore.runTransaction(transaction -> {
                DocumentReference userDoc = firestore.collection(COLLECTION_USERS).document(user.getId());
                transaction.update(userDoc, updateData);
                return null;
            }).get(); // Ensure transaction completes

            return user;
        }).subscribeOn(Schedulers.boundedElastic());
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
    public boolean isRetryableError(Throwable throwable) {
        return throwable instanceof CustomException &&
                ((CustomException) throwable).getStatusCode().is5xxServerError() ||
                throwable instanceof TimeoutException ||
                throwable instanceof FirebaseAuthException &&
                        ((FirebaseAuthException) throwable).getHttpResponse().getStatusCode() >= 500;
    }

    public Mono<Void> verifyEmail(String token, String ipAddress) {
        return Mono.defer(() -> {
            TokenClaims claims = jwtService.verifyEmailVerificationToken(token).block();

            return validateIpAddress(claims, ipAddress)
                    .then(updateUserVerificationStatus(claims.userId()))
                    .then(logSuccessfulVerification(claims, ipAddress));
        }).subscribeOn(Schedulers.boundedElastic());
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

