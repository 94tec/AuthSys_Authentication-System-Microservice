package com.techStack.authSys.service;

import com.google.cloud.Timestamp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.dto.AuthResult;
import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.event.AccountLockedEvent;
import com.techStack.authSys.event.AuthSuccessEvent;
import com.techStack.authSys.event.FirstLoginEvent;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.exception.EmailAlreadyExistsException;
import com.techStack.authSys.exception.NetworkException;
import com.techStack.authSys.exception.TransientAuthenticationException;
import com.techStack.authSys.models.*;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.repository.RateLimiterService;
import com.techStack.authSys.security.AccountStatusChecker;
import com.techStack.authSys.util.PasswordUtils;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.auth.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
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
import java.util.regex.Pattern;

@Service
@Slf4j
@RequiredArgsConstructor
public class SuperAdminService {
    private static final Logger logger = LoggerFactory.getLogger(SuperAdminService.class);

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration ATTEMPT_TTL = Duration.ofMinutes(10);
    private static final Duration BLOCK_DURATION = Duration.ofMinutes(5);
    private static final String LOGIN_FAIL_KEY_PREFIX = "login:fail:";
    private static final String LOGIN_BLOCK_KEY_PREFIX = "login:block:";

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final FirebaseAuth firebaseAuth;
    private final RedisCacheService redisCacheService;
    private final RedisService redisService;
    private final JwtService jwtService;
    private final AuditLogService auditLogService;
    private final MeterRegistry meterRegistry;
    private final RateLimiterService rateLimiterService;
    private final ApplicationEventPublisher eventPublisher;
    private final RateLimiterService.SessionService sessionService;
    private final AccountStatusChecker accountStatusChecker;
    private final PasswordExpiryService passwordExpiryService;
    private final MetricsService metricsService;
    private final DeviceVerificationService deviceVerificationService;
    private final EmailServiceInstance1 emailService;

    private final RoleAssignmentService roleAssignmentService;
    private final BootstrapFlagService bootstrapFlagService;

    private static final Pattern E164_PATTERN = Pattern.compile("^\\+?[1-9]\\d{1,14}$");

    public Mono<String> registerSuperAdmin(String email, String phone) {
        if (!StringUtils.hasText(email)) {
            return Mono.error(new IllegalArgumentException("Email parameter is required and cannot be empty"));
        }
        if (!StringUtils.hasText(phone)) {
            return Mono.error(new IllegalArgumentException("Phone parameter is required and cannot be empty"));
        }

        phone = normalizePhone(phone);

        if (!E164_PATTERN.matcher(phone).matches()) {
            return Mono.error(new IllegalArgumentException(
                    "Invalid phone number. Must be E.164 format, e.g., +254712345678"
            ));
        }

        String password = PasswordUtils.generateSecurePassword(16);
        long startTime = System.currentTimeMillis();

        log.info("🔐 Manual Super Admin registration initiated for email: {}", email);

        String finalPhone = phone;
        return isEmailTaken(email)
                .flatMap(emailExists -> {
                    if (emailExists) {
                        return Mono.error(new IllegalStateException("Super Admin already exists"));
                    }
                    return createSuperAdmin(email, finalPhone, password, startTime);
                });
    }

    private Mono<Boolean> isEmailTaken(String email) {
        return redisCacheService.isEmailRegistered(email)
                .onErrorResume(e -> {
                    log.warn("⚠️ Redis check failed for {}: {}", email, e.getMessage());
                    return Mono.just(false);
                })
                .flatMap(redisHit -> {
                    if (redisHit) return Mono.just(true);
                    return firebaseServiceAuth.findByEmail(email)
                            .map(user -> true)
                            .switchIfEmpty(Mono.just(false));
                });
    }

    private Mono<String> createSuperAdmin(String email, String phone,
                                          String password, long startTime) {
        User superAdmin = new User();
        superAdmin.setEmail(email);
        superAdmin.setPhoneNumber(phone);
        superAdmin.setPassword(password);
        superAdmin.setEmailVerified(true);
        superAdmin.setStatus(User.Status.ACTIVE);
        superAdmin.setEnabled(true);
        superAdmin.setForcePasswordChange(true);

        return firebaseServiceAuth.createSuperAdmin(superAdmin, password)
                .flatMap(firebaseUser -> Mono.zip(
                        roleAssignmentService.assignRoleAndPermissions(superAdmin, Roles.ADMIN),
                        roleAssignmentService.assignRoleAndPermissions(superAdmin, Roles.SUPER_ADMIN),
                        firebaseServiceAuth.saveUserPermissions(firebaseUser),
                        firebaseServiceAuth.saveUser(superAdmin, "127.0.0.1", "SYSTEM")
                ))
                .then(bootstrapFlagService.markBootstrapComplete())
                .then(Mono.defer(() -> {
                    redisCacheService.cacheRegisteredEmail(email);
                    return emailService.sendEmail(
                                    email,
                                    "Your Super Admin Account",
                                    STR."Welcome! Your temporary password is: \{password}"
                            )
                            .doOnError(e -> log.error("Failed to send welcome email", e))
                            .onErrorResume(e -> {
                                auditLogService.logAudit(
                                        superAdmin,
                                        ActionType.EMAIL_FAILURE,
                                        STR."Failed to send welcome email to \{email}",
                                        e.getMessage()
                                );
                                return Mono.empty();
                            })
                            .then(Mono.defer(() -> {
                                auditLogService.logAudit(
                                        superAdmin,
                                        ActionType.SUPER_ADMIN_CREATED,
                                        STR."Super admin created: \{superAdmin.getEmail()}",
                                        null
                                );

                                metricsService.incrementCounter("user.registration.success");
                                metricsService.recordTimer(
                                        "user.registration.time",
                                        Duration.ofMillis(System.currentTimeMillis() - startTime)
                                );

                                return Mono.just("Super admin created successfully.");
                            }));
                }));
    }

    private String normalizePhone(String phone) {
        if (!StringUtils.hasText(phone)) return null;

        phone = phone.trim().replaceAll("\\s+", "");

        if (phone.startsWith("0")) return "+254" + phone.substring(1);
        if (phone.startsWith("254")) return "+" + phone;
        if (!phone.startsWith("+")) return "+" + phone;
        return phone;
    }

    public Mono<AuthResult> login(String email, String password, String ipAddress,
                                  String deviceFingerprint, String userAgent,
                                  String issuedAt, String userId) {

        Timer.Sample timer = Timer.start(meterRegistry);

        return rateLimiterService.checkAuthRateLimit(ipAddress, email)
                .then(performAuthentication(email, password, issuedAt, ipAddress))
                .timeout(Duration.ofSeconds(20))
                .retryWhen(Retry.backoff(3, Duration.ofMillis(200))
                        .filter(this::shouldRetry)
                        .onRetryExhaustedThrow((spec, signal) ->
                                new AuthenticationException("Authentication service unavailable", signal.failure())))
                .doOnSuccess(authResult -> {
                    timer.stop(meterRegistry.timer("auth.success", "email", email, "ip", ipAddress));
                    handleSuccessfulAuth(authResult, ipAddress, deviceFingerprint);
                })
                .doOnError(error -> {
                    timer.stop(meterRegistry.timer("auth.failure", "email", email, "ip", ipAddress));
                    handleFailedAuth(email, ipAddress, deviceFingerprint, error);
                })
                .transform(firebaseServiceAuth::handleAuthErrors);
    }
    public Mono<AuthResult> performAuthentication(String email, String password, String issuedAt, String ipAddress) {
        return firebaseServiceAuth.getUserByEmail(email)
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(userRecord ->
                        firebaseServiceAuth.validateCredentials(email, password)
                                .then(accountStatusChecker.checkAccountStatus(email))
                                .then(passwordExpiryService.checkPasswordExpiry(userRecord.getUid(), password))
                                .then(firebaseServiceAuth.fetchUserDetailsWithPermissions(userRecord.getUid()))
                                .flatMap(user ->
                                        generateAndPersistTokens(
                                                user,
                                                ipAddress, // ✅ passed directly
                                                user.getDeviceFingerprint(),
                                                user.getUserAgent()
                                        )
                                )
                )
                .onErrorMap(firebaseServiceAuth::translateFirebaseException)
                .doOnSuccess(authResult -> firebaseServiceAuth.logAuthSuccess(email))
                .doOnError(e -> firebaseServiceAuth.logAuthFailure(email, e));
    }

    public Mono<AuthResult> generateAndPersistTokens(User user, String ipAddress, String deviceFingerprint, String userAgent) {
        Instant issuedAt = Instant.now();
        List<Roles> roleList = new ArrayList<>(user.getRoles());
        return jwtService.generateTokenPair(user, ipAddress, userAgent)
                .flatMap(tokens -> {
                    String sessionId = UUID.randomUUID().toString();
                    //Instant refreshExpiry = jwtService.getRefreshTokenExpiry();
                    return jwtService.getRefreshTokenExpiry(tokens.getRefreshToken())
                            .flatMap(refreshExpiry -> sessionService.createSession(
                                            user.getId(),
                                            sessionId,
                                            ipAddress,
                                            deviceFingerprint,
                                            tokens.getAccessToken(),
                                            tokens.getRefreshToken(),
                                            issuedAt,
                                            Timestamp.of(Date.from(refreshExpiry))
                                    )
                                    .thenReturn(new AuthResult(
                                            user,
                                            user.getId(),
                                            sessionId,
                                            tokens.getAccessToken(),
                                            tokens.getRefreshToken(),
                                            issuedAt,
                                            refreshExpiry,
                                            roleList,
                                            user.isMfaRequired(),
                                            user.getLoginAttempts(),
                                            issuedAt
                                    ))
                            );
                });
    }
    public boolean shouldRetry(Throwable throwable) {
        return throwable instanceof TransientAuthenticationException ||
                throwable instanceof NetworkException ||
                throwable instanceof java.net.SocketException;
    }
    private void handleSuccessfulAuth(AuthResult authResult, String ipAddress, String deviceFingerprint) {
        User user = authResult.getUser();

        // First login handling
        if (user.getLastLoginTimestamp() == null) {
            eventPublisher.publishEvent(new FirstLoginEvent(user, ipAddress));
        }

        // Update last login timestamp
        firebaseServiceAuth.updateLastLogin(user.getId(), ipAddress);

        // Publish authentication success event
        eventPublisher.publishEvent(new AuthSuccessEvent(user, ipAddress));

        // Log the success event
        log.info("Successful authentication \uD83D\uDD13 for user {} from IP: {} with Device Fingerprint: {}", user.getEmail(), ipAddress, deviceFingerprint);
    }

    public Mono<Void> invalidateRoleCaches(String userId) {
        return Mono.fromRunnable(() -> {
            redisCacheService.invalidateUserRoles(userId);
            redisCacheService.invalidateUserPermissions(userId);
        });
    }

    private Mono<Boolean> isBlocked(String email, String ip) {
        if (isWhitelisted(ip)) return Mono.just(false);
        return Mono.fromCallable(() -> redisService.getKey(STR."\{LOGIN_BLOCK_KEY_PREFIX}\{email}:\{ip}") != null);
    }

    private boolean requiresOtp(String email, String ip) {
        String key = STR."\{LOGIN_FAIL_KEY_PREFIX}\{email}:\{ip}";
        String attempts = String.valueOf(redisService.getKey(key));
        return attempts != null && Integer.parseInt(attempts) >= MAX_ATTEMPTS;
    }

    private void handleFailedAuth(String email, String ipAddress, String deviceFingerprint, Throwable error) {
        auditLogService.logAuthFailure(email, ipAddress, deviceFingerprint); // Log to audit

        // Track failed attempts and decide on account lockout
        rateLimiterService.recordFailedAttempt(email, ipAddress)
                .filter(shouldLock -> shouldLock)
                .flatMap(lock -> lockAccount(email))
                .subscribe();

        // Log failure
        log.warn("Authentication failed for {} from IP: {} with Device Fingerprint: {} - Error: {}", email, ipAddress, deviceFingerprint, error.getMessage());
    }
    private Mono<Void> lockAccount(String email) {
        return Mono.fromCallable(() -> {
                    UserRecord user = firebaseAuth.getUserByEmail(email);
                    firebaseAuth.updateUser(new UserRecord.UpdateRequest(user.getUid()).setDisabled(true));
                    eventPublisher.publishEvent(new AccountLockedEvent(user.getUid()));
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> log.warn("Account locked due to multiple failed attempts: {}", email)).then();
    }
    private Mono<Void> handleAttemptFail(String email, String ip) {
        String failKey = STR."\{LOGIN_FAIL_KEY_PREFIX}\{email}:\{ip}";
        String blockKey = STR."\{LOGIN_BLOCK_KEY_PREFIX}\{email}:\{ip}";
        return redisService.incrementValue(failKey, ATTEMPT_TTL)
                .flatMap(attemptsObj -> {
                    long attempts = ((Number) attemptsObj).longValue(); // Safe cast
                    if (attempts >= MAX_ATTEMPTS) {
                        return redisService.setKey(blockKey, "true", BLOCK_DURATION).then(logBlock(email, ip));
                    } else {
                        return logAttempt(email, ip);
                    }
                });
    }

    private Mono<Void> logBlock(String email, String ip) {
        return Mono.fromRunnable(() -> auditLogService.logAudit(User.builder().email(email).build(), ActionType.BLOCKED, "Too many login failures", ip));
    }

    private Mono<Void> logAttempt(String email, String ip) {
        return Mono.fromRunnable(() -> auditLogService.logAudit(User.builder().email(email).build(), ActionType.LOGIN_FAILED, "Login attempt failed", ip));
    }

    private Mono<Void> clearAttempts(String email, String ip) {
        return Mono.fromRunnable(() -> redisService.deleteKey(STR."\{LOGIN_FAIL_KEY_PREFIX}\{email}:\{ip}"));
    }

    private boolean isWhitelisted(String ip) {
        return ip.startsWith("127.") || ip.equals("localhost") || ip.equals("::1");
    }
    public Mono<Void> logout(String userId, String sessionId, String ipAddress) {
        return sessionService.invalidateSession(userId, sessionId)
                .doOnSuccess(v -> {
                    sessionService.invalidateUserSessions(userId); // Optional cache bust
                    auditLogService.logAudit(
                            User.builder().id(userId).build(),
                            ActionType.LOGOUT,
                            STR."User logged out. SessionId=\{sessionId}",
                            ipAddress
                    );
                    log.info("User {} logged out. SessionId={}", userId, sessionId);
                })
                .onErrorResume(ex -> {
                    log.error("Logout failed for userId={}, sessionId={}", userId, sessionId, ex);
                    return Mono.empty(); // Prevent error propagation during logout
                });
    }
    public Mono<User> createAdminUser(UserDTO userDto, ServerWebExchange exchange) {
        return getCreatorUidFromToken(exchange)
                .flatMap(creatorId -> {
                    log.info("Super Admin {} is creating an admin for email: {}", creatorId, userDto.getEmail());
                    return Mono.defer(() -> {
                        log.info("🔐 Admin registration attempt for email: {} from IP: {}",
                                userDto.getEmail(), exchange.getRequest().getRemoteAddress());

                        long startTime = System.currentTimeMillis();
                        String ipAddress = deviceVerificationService.extractClientIp(exchange);
                        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                                ipAddress, userDto.getUserAgent());

                        // Auto-generate password
                        String generatedPassword = PasswordUtils.generateSecurePassword(16);
                        userDto.setPassword(generatedPassword);
                        userDto.setForcePasswordChange(true);

                        return validateAndCreateAdmin(userDto, creatorId, ipAddress, deviceFingerprint, startTime);
                    });
                });
    }

    private Mono<User> validateAndCreateAdmin(UserDTO userDto, String creatorId, String ipAddress, String deviceFingerprint, long startTime) {
        return redisCacheService.isEmailRegistered(userDto.getEmail())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new EmailAlreadyExistsException());
                    }
                    return proceedWithAdminCreation(userDto, creatorId, ipAddress, deviceFingerprint, startTime);
                })
                .doOnError(e -> handleCreationError(e, userDto.getEmail(), startTime));
    }

    private Mono<User> proceedWithAdminCreation(UserDTO userDto, String creatorId, String ipAddress, String deviceFingerprint, long startTime) {
        return firebaseServiceAuth.createFirebaseUser(userDto, ipAddress, deviceFingerprint)
                .flatMap(user -> {
                    user.setDeviceFingerprint(deviceFingerprint);
                    user.setForcePasswordChange(true);
                    user.setCreatedBy(creatorId);

                    return deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint)
                            .then(sendWelcomeEmail(user, userDto.getPassword()))
                            .then(recordSuccessMetrics(user, ipAddress, creatorId, startTime))
                            .thenReturn(user);
                });
    }

    private Mono<Void> sendWelcomeEmail(User user, String tempPassword) {
        return Mono.fromRunnable(() -> emailService.sendEmail(
                user.getEmail(),
                "🔐 Your Admin Account Created",
                String.format(
                        "Welcome to the Admin Panel!\n\n" +
                                "Your account has been created by a Super Admin.\n\n" +
                                "Temporary Password: %s\n\n" +
                                "Please log in and change your password immediately.\n\n" +
                                "Thank you,\nThe Security Team",
                        tempPassword
                )
        ));
    }

    private Mono<Void> recordSuccessMetrics(User user, String ipAddress, String creatorId, long startTime) {
        return Mono.fromRunnable(() -> {
            long duration = System.currentTimeMillis() - startTime;
            log.info("✅ Admin registration completed for {} in {} ms", user.getEmail(), duration);
            auditLogService.logAudit(
                    user,
                    ActionType.ADMIN_CREATED,
                    String.format("Admin created by Super Admin: %s", creatorId),
                    ipAddress
            );
            redisCacheService.cacheRegisteredEmail(user.getEmail());
            metricsService.incrementCounter("user.registration.success");
            metricsService.recordTimer("user.registration.time", Duration.ofMillis(duration));
        });
    }

    private void handleCreationError(Throwable e, String email, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        log.error("❌ Admin registration failed for {} after {} ms: {}", email, duration, e.getMessage());
        metricsService.incrementCounter("user.registration.failure");

        if (e instanceof FirebaseAuthException && "EMAIL_EXISTS".equals(((FirebaseAuthException) e).getErrorCode())) {
            firebaseServiceAuth.cleanupFailedRegistration(email).subscribe();
        }
    }
    // Gets Creator User ID from Token
    public Mono<String> getCreatorUidFromToken(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .map(token -> token.replace("Bearer ", "").trim())
                .flatMap(idToken ->
                        jwtService.validateToken(idToken, "access")  // Or just validate(idToken) if no type
                                .flatMap(claims -> {
                                    //log.info(claims.getId());
                                    // Check if claims is valid and contains expected info
                                    if (claims == null || claims.get("sub") == null) {
                                        return Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "Invalid or expired token"));
                                    }
                                    // Extract the UID (or any other claim you need)
                                    return Mono.just((String) claims.get("sub"));  // "sub" is typically the user or UID
                                })
                );
    }

}
