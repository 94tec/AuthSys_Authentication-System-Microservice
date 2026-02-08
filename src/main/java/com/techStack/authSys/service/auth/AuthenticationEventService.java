package com.techStack.authSys.service.auth;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.event.AccountLockedEvent;
import com.techStack.authSys.event.AuthSuccessEvent;
import com.techStack.authSys.event.FirstLoginEvent;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.repository.sucurity.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;

/**
 * Handles authentication-related events and side effects.
 * Manages success/failure logging, event publishing, and account locking.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationEventService {

    private final FirebaseAuth firebaseAuth;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AuditLogService auditLogService;
    private final RateLimiterService rateLimiterService;
    private final ApplicationEventPublisher eventPublisher;

    @Value("${security.auth.max-attempts:5}")
    private int maxAuthAttempts;

    @Value("${security.auth.lockout-minutes:30}")
    private int lockoutMinutes;

    /**
     * Handles successful authentication events.
     * Updates last login, publishes events, and logs success.
     */
    public void handleSuccessfulAuthentication(
            AuthResult authResult,
            String ipAddress,
            Instant timestamp,
            String deviceFingerprint,
            String userAgent) {

        User user = authResult.getUser();

        // Check if this is first login
        if (isFirstLogin(user)) {
            publishFirstLoginEvent(user, ipAddress, timestamp, deviceFingerprint);
        }

        // Update last login timestamp
        updateLastLogin(user.getId(), ipAddress);

        // Publish success event
        publishAuthSuccessEvent(user, ipAddress, timestamp,deviceFingerprint, userAgent);

        // Log success
        logSuccessfulAuth(user.getEmail(), ipAddress, deviceFingerprint);
    }

    /**
     * Handles failed authentication events.
     * Records failure, checks for account lockout, and logs.
     */
    public void handleFailedAuthentication(
            String email,
            Object source,
            Instant timestamp,
            String ipAddress,
            String deviceFingerprint,
            String reason,
            Throwable error) {

        // Audit log the failure
        auditLogService.logAuthFailure(email, ipAddress, deviceFingerprint, error.getMessage());

        // Track failed attempts and lock account if threshold exceeded
        recordFailedAttemptAndCheckLockout(email, source, timestamp, reason, ipAddress);

        // Log failure
        logFailedAuth(email, ipAddress, deviceFingerprint, error);
    }


    /**
     * Event listener for account locked events.
     * Sends notifications, logs, etc.
     */
    @Async
    @EventListener
    public void handleAccountLockedEvent(AccountLockedEvent event) {
        log.warn("Account locked event received for user: {}", event.getUserId());
        // Additional logic: send email notification, trigger alerts, etc.
    }

    /**
     * Checks if this is the user's first login.
     */
    private boolean isFirstLogin(User user) {
        return user.getLastLogin() == null;
    }

    /**
     * Publishes first login event for new user onboarding.
     */
    private void publishFirstLoginEvent(User user, String ipAddress, Instant timestamp, String deviceFingerprint) {
        try {
            eventPublisher.publishEvent(new FirstLoginEvent(user, ipAddress, timestamp, deviceFingerprint));
            log.info("First login detected for user: {}", user.getEmail());
        } catch (Exception e) {
            log.warn("Failed to publish first login event: {}", e.getMessage());
        }
    }

    /**
     * Updates user's last login timestamp.
     */
    private void updateLastLogin(String userId, String ipAddress) {
        try {
            firebaseServiceAuth.updateLastLogin(userId, ipAddress);
        } catch (Exception e) {
            log.warn("Failed to update last login for user {}: {}", userId, e.getMessage());
        }
    }

    /**
     * Publishes authentication success event.
     */
    private void publishAuthSuccessEvent(User user, String ipAddress, Instant timestamp, String deviceFingerprint, String userAgent) {
        try {
            eventPublisher.publishEvent(new AuthSuccessEvent(user, ipAddress, timestamp, deviceFingerprint, userAgent));
        } catch (Exception e) {
            log.warn("Failed to publish auth success event: {}", e.getMessage());
        }
    }

    /**
     * Logs successful authentication.
     */
    private void logSuccessfulAuth(String email, String ipAddress, String deviceFingerprint) {
        log.info("✅ Successful authentication for user: {} from IP: {} with device: {}",
                email, ipAddress, deviceFingerprint);
    }

    /**
     * Records failed attempt and checks if account should be locked.
     */
    private void recordFailedAttemptAndCheckLockout(String email,Object source, Instant timestamp, String reason, String ipAddress) {
        rateLimiterService.recordFailedAttempt(email, ipAddress)
                .filter(shouldLock -> shouldLock)
                .flatMap(shouldLock -> lockAccount(email, source, timestamp, reason, ipAddress))
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe(
                        v -> log.warn("Account locked due to multiple failed attempts: {}", email),
                        e -> log.error("Failed to lock account: {}", email, e)
                );
    }

    /**
     * Locks a user account due to excessive failed login attempts.
     */
    private Mono<Void> lockAccount(String email, Object source, Instant timestamp, String reason, String ipAddress) {
        return Mono.fromCallable(() -> {
                    UserRecord user = firebaseAuth.getUserByEmail(email);
                    firebaseAuth.updateUser(
                            new UserRecord.UpdateRequest(user.getUid())
                                    .setDisabled(true)
                    );
                    eventPublisher.publishEvent(new AccountLockedEvent(source, user.getUid(), timestamp, reason, ipAddress));
                    return null;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> log.warn("🔒 Account locked: {}", email))
                .doOnError(e -> log.error("Failed to lock account {}: {}", email, e.getMessage()))
                .then();
    }

    /**
     * Logs failed authentication attempt.
     */
    private void logFailedAuth(String email, String ipAddress, String deviceFingerprint, Throwable error) {
        log.warn("❌ Authentication failed for {} from IP: {} with device: {} - Error: {}",
                email, ipAddress, deviceFingerprint, error.getMessage());
    }
}
