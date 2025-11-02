package com.techStack.authSys.service;

import com.google.api.client.util.Value;
import com.google.cloud.Timestamp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.dto.AuthResult;
import com.techStack.authSys.event.AccountLockedEvent;
import com.techStack.authSys.event.AuthSuccessEvent;
import com.techStack.authSys.event.FirstLoginEvent;
import com.techStack.authSys.exception.AuthException;
import com.techStack.authSys.exception.NetworkException;
import com.techStack.authSys.exception.TransientAuthenticationException;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.repository.AuthServiceController;
import com.techStack.authSys.security.AccountStatusChecker;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.auth.AuthenticationException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthServiceController {

    private final FirebaseAuth firebaseAuth;
    private final PasswordExpiryService passwordExpiryService;
    private final AuditLogService auditLogService;
    private final AccountStatusChecker accountStatusChecker;
    private final ApplicationEventPublisher eventPublisher;
    private final RateLimiterService rateLimiterService;
    private final MeterRegistry meterRegistry;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final JwtService jwtService;
    private final RateLimiterService.SessionService sessionService;

    @Value("${security.auth.max-attempts:5}")
    private int maxAuthAttempts;
    @Value("${security.auth.lockout-minutes:30}")
    private int lockoutMinutes;

    @Override
    public void handleAccountLockedEvent(AccountLockedEvent event) {

    }

    @Override
    public Mono<AuthResult> authenticate(String email, String password, String ipAddress,
                                         String deviceFingerprint, String userAgent,
                                         String issuedAt, String userId) {
        Timer.Sample timer = Timer.start(meterRegistry);

        return Mono.defer(() ->
                        rateLimiterService.checkAuthRateLimit(ipAddress, email)
                                .then(performAuthentication(email, password, issuedAt, ipAddress))
                                .timeout(Duration.ofSeconds(20))
                                .retryWhen(Retry.backoff(3, Duration.ofMillis(100))
                                        .filter(this::shouldRetry)
                                        .onRetryExhaustedThrow((spec, signal) ->
                                                new AuthException("Authentication service unavailable", HttpStatus.SERVICE_UNAVAILABLE))
                                )
                )
                .doOnSuccess(authResult -> {
                    timer.stop(meterRegistry.timer("auth.success"));
                    handleSuccessfulAuth(authResult, ipAddress, deviceFingerprint);
                })
                .doOnError(e -> {
                    timer.stop(meterRegistry.timer("auth.failure"));
                    handleFailedAuth(email, ipAddress, deviceFingerprint, e);
                })
                // Ensure all errors are converted to AuthException
                .onErrorResume(e -> {
                    if (e instanceof AuthException) {
                        return Mono.error(e);
                    }
                    // Convert any other exception to AuthException
                    return Mono.error(new AuthException(
                            "Authentication failed. Please try again.",
                            HttpStatus.UNAUTHORIZED
                    ));
                });
    }

    @Override
    public Mono<AuthResult> performAuthentication(String email, String password, String ipAddress, String deviceFingerprint, String issuedAt) {
        return null;
    }

    // Helper method for filtering retryable exceptions
    public boolean shouldRetry(Throwable throwable) {
        return throwable instanceof TransientAuthenticationException ||
                throwable instanceof NetworkException;
    }

    @Override
    public Mono<AuthResult> performAuthentication(String email, String password, String issuedAt, String ipAddress) {
        return Mono.defer(() -> firebaseServiceAuth.getUserByEmail(email)) // Fetch user by email
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(userRecord ->
                        firebaseServiceAuth.validateCredentials(email, password) // Validate credentials
                                .then(accountStatusChecker.checkAccountStatus(email)) // Check account status
                                .then(passwordExpiryService.checkPasswordExpiry(userRecord.getUid(), password)) // Check password expiry
                                .then(firebaseServiceAuth.fetchUserDetailsWithPermissions(userRecord.getUid())) // Fetch user details with permissions
                                .flatMap(user ->
                                        generateAndPersistTokens(
                                                user,
                                                ipAddress, // ✅ passed directly
                                                user.getDeviceFingerprint(),
                                                user.getUserAgent()
                                        )
                                )
                )
                .onErrorMap(e -> {
                    if (e instanceof AuthException) {
                        return e; // Already an AuthException
                    }
                    return firebaseServiceAuth.translateFirebaseException(e);
                })
                .doOnError(e -> {
                    if (e instanceof AuthException) {
                        firebaseServiceAuth.logAuthFailure(email, e);
                    }
                })
                .doOnSuccess(authResult -> firebaseServiceAuth.logAuthSuccess(email));
    }

    @Override
    public Mono<AuthResult> generateAndPersistTokens(User user, String ipAddress, String deviceFingerprint, String userAgent) {
        Instant issuedAt = Instant.now();
        List<Roles> roleList = new ArrayList<>(user.getRoles());
        return jwtService.generateTokenPair(user, ipAddress, userAgent)
                .flatMap(tokens -> {
                    String sessionId = UUID.randomUUID().toString();
                    Instant refreshExpiry = jwtService.getRefreshTokenExpiry(tokens.getRefreshToken()).block();

                    return sessionService.createSession(
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
                            ));
                });
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
        log.info("Successful authentication for user {} from IP: {} with Device Fingerprint: {}", user.getEmail(), ipAddress, deviceFingerprint);
    }

    private void handleFailedAuth(String email, String ipAddress, String deviceFingerprint, Throwable error) {
        auditLogService.logAuthFailure(email, ipAddress, deviceFingerprint, error.getMessage()); // Log to audit

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

}
