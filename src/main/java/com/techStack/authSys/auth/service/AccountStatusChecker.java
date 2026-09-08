package com.techStack.authSys.auth.service;

import com.techStack.authSys.auth.exception.EmailNotVerifiedException;
import com.techStack.authSys.auth.exception.TransientAuthenticationException;
import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.identity.exception.AccountDisabledException;
import com.techStack.authSys.identity.exception.AccountLockedException;
import com.techStack.authSys.identity.exception.AccountNotFoundException;
import com.techStack.authSys.identity.models.User;
import com.techStack.authSys.security.audit.AuditLogService;
import com.techStack.authSys.security.service.AccountLockServiceImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Account Status Checker
 *
 * Validates account status before authentication.
 * Uses Clock for timestamp tracking.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AccountStatusChecker {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AccountLockServiceImpl accountLockServiceImpl;
    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       Main Validation
       ========================= */

    /**
     * Check account status before authentication
     */
    public Mono<User> checkAccountStatus(String email) {
        Instant now = clock.instant();
        log.info("Checking account status for email: {} at {}", email, now);

        return firebaseServiceAuth.findByEmail(email)
                .timeout(Duration.ofSeconds(8), Mono.error(
                        new TransientAuthenticationException(
                                "Account lookup timed out for " + HelperUtils.maskEmail(email))))
                .doOnSuccess(user -> log.info("Found user: {} at {}", user.getEmail(), now))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Account not found for email: {} at {}", email, now);
                    return Mono.error(new AccountNotFoundException("User not found"));
                }))
                .flatMap(user -> validateAccount(user, now).thenReturn(user))
                .doOnError(e -> log.error("Account status check failed for email {} at {}: {}",
                        email, now, e.getMessage()));
    }

    /* =========================
       Validation Methods
       ========================= */

    /**
     * Perform all account validation checks
     */
    private Mono<Void> validateAccount(User user, Instant timestamp) {
        return Mono.when(
                validateAccountActive(user, timestamp),
                validateEmailVerified(user, timestamp),
                validateAccountNotLocked(user, timestamp)
        );
    }

    /**
     * Ensure account is active
     */
    private Mono<Void> validateAccountActive(User user, Instant timestamp) {
        if (!user.isEnabled()) {
            log.warn("Account is disabled for user ID: {} at {}. Login attempt blocked.",
                    user.getId(), timestamp);

            auditLogService.logSecurityEvent(
                    "DISABLED_ACCOUNT_ACCESS_ATTEMPT",
                    user.getId(),
                    "Attempted login to disabled account at " + timestamp
            );

            return Mono.error(new AccountDisabledException("Account is disabled"));
        }
        return Mono.empty();
    }

    /**
     * Ensure email is verified
     */
    private Mono<Void> validateEmailVerified(User user, Instant timestamp) {
        if (!user.isEmailVerified()) {
            log.warn("Email not verified for user ID: {} at {}. Login attempt blocked.",
                    user.getId(), timestamp);

            auditLogService.logSecurityEvent(
                    "UNVERIFIED_EMAIL_LOGIN_ATTEMPT",
                    user.getId(),
                    "Attempted login with unverified email at " + timestamp
            );

            return Mono.error(new EmailNotVerifiedException("Email not verified"));
        }
        return Mono.empty();
    }

    /**
     * Ensure account is not locked
     */
    // AccountStatusChecker.java
    private Mono<Void> validateAccountNotLocked(User user, Instant timestamp) {
        return Mono.fromCallable(() -> accountLockServiceImpl.isAccountLocked(user.getId()))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(locked -> {
                    if (!locked) {
                        return Mono.empty();
                    }
                    log.warn("Account is locked for user ID: {} at {}. Login attempt blocked.",
                            user.getId(), timestamp);

                    Duration lockDuration = accountLockServiceImpl.getLockDuration(user.getId())
                            .orElse(Duration.ofMinutes(15));
                    Instant unlockTime = timestamp.plus(lockDuration);
                    int lockoutMinutes = (int) lockDuration.toMinutes();

                    auditLogService.logSecurityEvent(
                            "ACCOUNT_LOCKED_ACCESS_ATTEMPT",
                            user.getId(),
                            String.format("Attempted login to locked account at %s. Unlocks at %s",
                                    timestamp, unlockTime)
                    );

                    return Mono.error(new AccountLockedException(lockoutMinutes, unlockTime));
                });
    }
}