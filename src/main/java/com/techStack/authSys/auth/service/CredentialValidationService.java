package com.techStack.authSys.auth.service;

import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.auth.exception.AuthException;
import com.techStack.authSys.auth.exception.PasswordExpiredException;
import com.techStack.authSys.auth.exception.PasswordWarningException;
import com.techStack.authSys.auth.exception.TransientAuthenticationException;
import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.identity.models.User;
import com.techStack.authSys.security.audit.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * Credential Validation Service
 *
 * Coordinates credential validation and account checks with Clock-based tracking.
 * Delegates to specialized services:
 * - FirebaseAuthValidator: Credential validation
 * - AccountStatusChecker: Account status checks
 * - PasswordExpiryService: Password expiry validation
 * - FirebaseServiceAuth: User data retrieval
 * - AuditLogService: Authentication audit logging
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialValidationService {

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseAuthValidator firebaseAuthValidator;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AccountStatusChecker accountStatusChecker;
    private final PasswordExpiryService passwordExpiryService;
    private final AuditLogService auditLogService;
    private final Clock clock;

    /* =========================
       Main Validation Flow
       ========================= */

    /**
     * Validates user credentials and performs all account checks.
     *
     * Flow:
     * 1. Validate credentials against Firebase
     * 2. Check account status (disabled, locked, email verified)
     * 3. Check password expiry
     * 4. Fetch full user details with permissions
     * 5. Log authentication result
     *
     * @param email User email
     * @param password User password
     * @param ipAddress Client IP address
     * @param deviceFingerprint Device fingerprint
     * @return Mono of User with full details and permissions
     */
    public Mono<User> validateAndFetchUser(
            String email,
            String password,
            String ipAddress,
            String deviceFingerprint) {

        Instant validationStart = clock.instant();

        log.info("Credential validation started at {} for: {} from IP: {}",
                validationStart,
                HelperUtils.maskEmail(email),
                ipAddress);

        return performValidationChain(email, password, ipAddress, deviceFingerprint, validationStart)
                .doOnSuccess(user -> {
                    Instant validationEnd = clock.instant();
                    Duration duration = Duration.between(validationStart, validationEnd);

                    handleSuccessfulValidation(user, email, ipAddress, validationEnd, duration);
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(validationStart, errorTime);

                    handleFailedValidation(e, email, ipAddress, deviceFingerprint, errorTime, duration);
                });
    }

    /* =========================
       Validation Chain
       ========================= */

    /**
     * Performs the complete validation chain
     */
    private Mono<User> performValidationChain(
            String email,
            String password,
            String ipAddress,
            String deviceFingerprint,
            Instant validationStart) {

        return validateCredentials(email, password, validationStart)
                .then(checkAccountStatus(email, validationStart))
                .flatMap(user -> checkPasswordExpiry(user, password, validationStart))
                .flatMap(user -> fetchUserWithPermissions(user, validationStart))
                .onErrorMap(e -> translateException(e, email, ipAddress));
    }

    /* =========================
       Step 1: Credential Validation
       ========================= */

    /**
     * Validate credentials against Firebase Auth
     */
    private Mono<Void> validateCredentials(
            String email,
            String password,
            Instant validationStart) {

        Instant credentialCheckStart = clock.instant();

        log.debug("Validating credentials at {} for: {}",
                credentialCheckStart, HelperUtils.maskEmail(email));

        return firebaseServiceAuth.validateCredentials(email, password)
                .timeout(Duration.ofSeconds(8), Mono.error(
                        new TransientAuthenticationException("Credential validation timed out")))
                .doOnSuccess(v -> {
                    Instant credentialCheckEnd = clock.instant();
                    Duration duration = Duration.between(credentialCheckStart, credentialCheckEnd);

                    log.info("✅ Credentials validated at {} in {} for: {}",
                            credentialCheckEnd,
                            duration,
                            HelperUtils.maskEmail(email));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(credentialCheckStart, errorTime);

                    log.warn("❌ Credential validation failed at {} after {} for {}: {}",
                            errorTime,
                            duration,
                            HelperUtils.maskEmail(email),
                            e.getMessage());
                });
    }

    /* =========================
       Step 2: Account Status Check
       ========================= */

    /**
     * Check account status (enabled, not locked, email verified)
     */
    private Mono<User> checkAccountStatus(String email, Instant validationStart) {
        Instant statusCheckStart = clock.instant();

        log.debug("Checking account status at {} for: {}",
                statusCheckStart, HelperUtils.maskEmail(email));

        return accountStatusChecker.checkAccountStatus(email)
                .doOnSuccess(user -> {
                    Instant statusCheckEnd = clock.instant();
                    Duration duration = Duration.between(statusCheckStart, statusCheckEnd);

                    log.info("✅ Account status check passed at {} in {} for: {} (Status: {}, Enabled: {}, Verified: {})",
                            statusCheckEnd,
                            duration,
                            HelperUtils.maskEmail(email),
                            user.getStatus(),
                            user.isEnabled(),
                            user.isEmailVerified());
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(statusCheckStart, errorTime);

                    log.warn("❌ Account status check failed at {} after {} for {}: {}",
                            errorTime,
                            duration,
                            HelperUtils.maskEmail(email),
                            e.getMessage());
                });
    }

    /* =========================
   Step 3: Password Expiry Check
   ========================= */

    /**
     * Verify that password hasn't expired.
     *
     * IMPORTANT: password expiry is advisory, not a hard authentication gate.
     * A genuine PasswordExpiredException/PasswordWarningException reflects a
     * real fact about the user's credential and must propagate. Any other
     * failure here (Firestore unavailable, credential/token refresh errors,
     * network blips) means we simply couldn't determine expiry — that is NOT
     * grounds to deny a user who has already passed Firebase credential
     * validation and an active/enabled/verified account status check. Treat
     * those as "unknown, proceed" rather than "denied."
     */
    private Mono<User> checkPasswordExpiry(
            User user,
            String password,
            Instant validationStart) {

        Instant expiryCheckStart = clock.instant();

        log.debug("Checking password expiry at {} for user: {}",
                expiryCheckStart, user.getId());

        return passwordExpiryService.checkPasswordExpiry(user.getId(), password)
                .thenReturn(user)
                .doOnSuccess(u -> {
                    Instant expiryCheckEnd = clock.instant();
                    Duration duration = Duration.between(expiryCheckStart, expiryCheckEnd);

                    log.info("✅ Password expiry check passed at {} in {} for user: {}",
                            expiryCheckEnd,
                            duration,
                            user.getId());
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(expiryCheckStart, errorTime);

                    if (e instanceof PasswordExpiredException || e instanceof PasswordWarningException) {
                        // A real, meaningful outcome about this user's credential — must propagate.
                        log.warn("❌ Password expiry check failed at {} after {} for user {}: {}",
                                errorTime, duration, user.getId(), e.getMessage());
                        return Mono.error(e);
                    }

                    // Infrastructure/transient failure — we don't know the answer, but the
                    // user already passed real credential + account-status checks. Don't
                    // deny login over an inconclusive check.
                    log.warn("⚠️ Password expiry check inconclusive at {} after {} for user {} "
                                    + "(non-blocking — allowing login): {}",
                            errorTime, duration, user.getId(), e.getMessage());
                    return Mono.just(user);
                });
    }


    /* =========================
       Step 4: Fetch User Details
       ========================= */

    /**
     * Fetch complete user details including roles and permissions
     */
    private Mono<User> fetchUserWithPermissions(User user, Instant validationStart) {
        Instant fetchStart = clock.instant();

        log.debug("Fetching user details at {} for user: {}", fetchStart, user.getId());

        return firebaseServiceAuth.fetchUserDetailsWithPermissions(user.getId())
                .timeout(Duration.ofSeconds(8), Mono.error(
                                new TransientAuthenticationException("User/permissions fetch timed out")))
                .doOnSuccess(fullUser -> {
                    Instant fetchEnd = clock.instant();
                    Duration duration = Duration.between(fetchStart, fetchEnd);

                    log.info("✅ User details fetched at {} in {} - ID: {}, Roles: {}, Permissions: {}",
                            fetchEnd,
                            duration,
                            fullUser.getId(),
                            fullUser.getRoleNames(),
                            fullUser.getAllPermissions().size());
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(fetchStart, errorTime);

                    log.error("❌ Failed to fetch user details at {} after {} for user {}: {}",
                            errorTime,
                            duration,
                            user.getId(),
                            e.getMessage());
                });
    }

    /* =========================
       Success & Error Handling
       ========================= */

    /**
     * Handle successful validation
     */
    private void handleSuccessfulValidation(
            User user,
            String email,
            String ipAddress,
            Instant completionTime,
            Duration totalDuration) {

        log.info("✅ Credential validation completed successfully at {} in {} for: {} | ID: {} | Roles: {}",
                completionTime,
                totalDuration,
                HelperUtils.maskEmail(email),
                user.getId(),
                user.getRoleNames());

        // Log successful authentication
        try {
            auditLogService.logLoginAttempt(email, ipAddress, true);
        } catch (Exception e) {
            log.warn("Failed to log successful authentication (non-critical): {}", e.getMessage());
        }
    }

    /**
     * Handle failed validation
     */
    private void handleFailedValidation(
            Throwable error,
            String email,
            String ipAddress,
            String deviceFingerprint,
            Instant errorTime,
            Duration totalDuration) {

        log.error("❌ Credential validation failed at {} after {} for {}: {} - {}",
                errorTime,
                totalDuration,
                HelperUtils.maskEmail(email),
                error.getClass().getSimpleName(),
                error.getMessage());

        // Log failed authentication
        try {
            if (error instanceof AuthException authEx) {
                auditLogService.logAuthFailure(
                        email,
                        ipAddress,
                        deviceFingerprint,
                        authEx.getMessage()
                );
            } else {
                auditLogService.logLoginAttempt(email, ipAddress, false);
            }
        } catch (Exception e) {
            log.error("Failed to log authentication failure (critical): {}", e.getMessage());
        }
    }

    /**
     * Translate exceptions to AuthException
     */
    private Throwable translateException(Throwable e, String email, String ipAddress) {
        if (e instanceof AuthException) {
            return e;
        }

        Instant errorTime = clock.instant();

        log.error("Translating exception at {} for {}: {} -> AuthException",
                errorTime,
                HelperUtils.maskEmail(email),
                e.getClass().getSimpleName());

        return firebaseAuthValidator.translateFirebaseException(e);
    }

    /* =========================
       Simplified Overload
       ========================= */

    /**
     * Simplified validation without device tracking
     */
    public Mono<User> validateAndFetchUser(String email, String password) {
        return validateAndFetchUser(email, password, "UNKNOWN", "UNKNOWN");
    }

}