package com.techStack.authSys.auth.service;

import com.techStack.authSys.auth.event.EventPublisherService;
import com.techStack.authSys.auth.exception.*;
import com.techStack.authSys.auth.jwt.PasswordResetTokenService;
import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.identity.dto.UserRegistrationDTO;
import com.techStack.authSys.identity.exception.UserNotFoundException;
import com.techStack.authSys.identity.models.User;
import com.techStack.authSys.identity.service.EmailValidationService;
import com.techStack.authSys.notification.service.EmailServiceInstance;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Password Reset Service
 *
 * Handles password reset workflows with Clock-based timestamp tracking.
 * Includes token generation, validation, and password update operations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    /* =========================
       Constants
       ========================= */

    private static final int MAX_RETRIES = 3;
    private static final Duration RETRY_DELAY = Duration.ofMillis(500);
    private static final Duration TOKEN_VALIDITY = Duration.ofHours(1);

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PasswordEncoder passwordEncoder;
    private final EmailServiceInstance emailService;
    private final PasswordResetTokenService tokenService;
    private final PasswordPolicyService passwordPolicyService;
    private final EmailValidationService  emailValidationService;
    private final EventPublisherService eventPublisherService;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${app.frontend-base-url}")
    private String frontendUrl;

    private static final String RESET_TEMPLATE = "emails/auth/password-reset";
    private static final String RESET_SUBJECT = "Password Reset Request";

    /* =========================
       Password Reset Initiation
       ========================= */

    /**
     * Initiate password reset process
     */
    public Mono<String> initiatePasswordReset(String email) {
        Instant initiateTime = clock.instant();

        log.info("Initiating password reset at {} for email: {}",
                initiateTime, HelperUtils.maskEmail(email));

        return validateEmail(email)
                .flatMap(validEmail -> validateDomain(validEmail, initiateTime))
                .flatMap(this::findUserByEmail)
                .flatMap(user -> generateAndStoreToken(user.getEmail(), initiateTime))
                .flatMap(token -> sendResetEmail(email, token))
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRecoverableError)
                        .doBeforeRetry(retrySignal -> {
                            Instant retryTime = clock.instant();
                            log.warn("Retrying password reset at {} - Attempt: {}",
                                    retryTime, retrySignal.totalRetries() + 1);
                        })
                )
                .doOnSuccess(token -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(initiateTime, completionTime);

                    log.info("✅ Password reset initiated successfully at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(email));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(initiateTime, errorTime);

                    log.error("❌ Failed to initiate password reset at {} after {} for {}: {}",
                            errorTime, duration, HelperUtils.maskEmail(email), e.getMessage(), e);
                });
    }

    /**
     * Validate email format
     */
    private Mono<String> validateEmail(String email) {
        Instant validationTime = clock.instant();

        return Mono.just(email)
                .filter(e -> e != null && !e.isBlank() && e.contains("@"))
                .doOnNext(validEmail -> log.debug("Email validated at {}: {}",
                        validationTime, HelperUtils.maskEmail(validEmail)))
                .switchIfEmpty(Mono.error(() -> {
                    log.warn("Invalid email format at {}: {}",
                            validationTime, HelperUtils.maskEmail(email));
                    return new IllegalArgumentException("Invalid email format");
                }));
    }

    /**
     * Validate email domain
     */
    private Mono<String> validateDomain(String email, Instant initiateTime) {

        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setEmail(email);

        return emailValidationService.validateEmail(email)
                .then(Mono.fromCallable(() -> {
                    log.debug("✅ Domain validated at {} for: {}",
                            clock.instant(), HelperUtils.maskEmail(email));
                    return email;
                }))
                .onErrorResume(e -> {
                    // graceful degradation
                    log.warn("⚠️ Domain validation error at {}, continuing: {}",
                            clock.instant(), e.getMessage());
                    return Mono.just(email);
                });
    }


    /**
     * Find user by email
     */
    private Mono<User> findUserByEmail(String email) {
        Instant lookupTime = clock.instant();

        return firebaseServiceAuth.findByEmail(email)
                .doOnSuccess(user -> {
                    if (user != null) {
                        log.debug("User found at {} for: {}",
                                clock.instant(), HelperUtils.maskEmail(email));
                    }
                })
                .switchIfEmpty(Mono.defer(() -> {
                    Instant errorTime = clock.instant();
                    log.warn("User not found at {} for: {}",
                            errorTime, HelperUtils.maskEmail(email));
                    return Mono.error(new UserNotFoundException(
                            HttpStatus.NOT_FOUND,
                            "User not found"
                    ));
                }));
    }

    /**
     * Generate and store reset token
     */
    private Mono<String> generateAndStoreToken(String email, Instant initiateTime) {
        Instant tokenGenTime = clock.instant();
        String token = UUID.randomUUID().toString();

        log.debug("Generating reset token at {} for: {}",
                tokenGenTime, HelperUtils.maskEmail(email));

        return tokenService.saveResetToken(email, token)
                .doOnSuccess(saved -> {
                    Instant savedTime = clock.instant();
                    Duration duration = Duration.between(tokenGenTime, savedTime);

                    log.info("Reset token saved at {} in {} for: {}",
                            savedTime, duration, HelperUtils.maskEmail(email));
                })
                .thenReturn(token)
                .onErrorMap(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to generate token at {} for {}: {}",
                            errorTime, HelperUtils.maskEmail(email), e.getMessage());
                    return new TokenGenerationException("Failed to generate reset token", e);
                });
    }

    /**
     * Send password reset email using HTML template.
     * Returns the token on success for chaining.
     */
    public Mono<String> sendResetEmail(String email, String token) {
        Instant startedAt = clock.instant();
        String maskedEmail = HelperUtils.maskEmail(email);

        String resetLink = buildResetLink(token);

        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", deriveDisplayName(email));
        variables.put("resetLink", resetLink);

        log.debug("Sending password reset email to {} at {}", maskedEmail, startedAt);

        return emailService.sendTemplatedEmail(email, RESET_SUBJECT, RESET_TEMPLATE, variables)
                .doOnSuccess(v -> log.info("📧 Reset email sent to {} in {}",
                        maskedEmail, Duration.between(startedAt, clock.instant())))
                .doOnError(e -> log.error("❌ Failed to send reset email to {} after {}: {}",
                        maskedEmail, Duration.between(startedAt, clock.instant()), e.getMessage()))
                .thenReturn(token)
                .onErrorMap(e -> new EmailSendingException("Failed to send password reset email", e));
    }

    private String buildResetLink(String token) {
        return UriComponentsBuilder.fromHttpUrl(frontendUrl)
                .path("/password-reset")
                .queryParam("token", token)
                .build()
                .toUriString();
    }

    /**
     * Best-effort display name from the email local-part until you have a
     * real first-name field available at this call site.
     */
    private String deriveDisplayName(String email) {
        String localPart = email.split("@")[0];
        return localPart.isBlank() ? "there" : localPart;
    }

    /* =========================
       Token Validation
       ========================= */

    /**
     * Validate reset token
     */
    public Mono<Boolean> validateResetToken(String token) {
        Instant validationTime = clock.instant();

        log.debug("Validating reset token at {}", validationTime);

        return tokenService.tokenExists(token)
                .doOnSuccess(exists -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(validationTime, completionTime);

                    log.info("Token validation completed at {} in {} - Exists: {}",
                            completionTime, duration, exists);
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Token validation error at {}: {}", errorTime, e.getMessage());
                    return Mono.just(false);
                });
    }

    /* =========================
       Password Reset Completion
       ========================= */

    /**
     * Reset password using token
     */
    public Mono<User> resetPassword(String token, String newPassword, String ipAddress) {
        Instant resetTime = clock.instant();

        log.info("Password reset process started at {}", resetTime);

        return validatePassword(newPassword)
                .flatMap(validPassword -> processPasswordReset(token, validPassword, resetTime, ipAddress))
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRecoverableError)
                        .doBeforeRetry(retrySignal -> {
                            Instant retryTime = clock.instant();
                            log.warn("Retrying password reset at {} - Attempt: {}",
                                    retryTime, retrySignal.totalRetries() + 1);
                        })
                )
                .doOnSuccess(user -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(resetTime, completionTime);

                    log.info("✅ Password reset completed at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(user.getEmail()));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(resetTime, errorTime);

                    log.error("❌ Password reset failed at {} after {}: {}",
                            errorTime, duration, e.getMessage(), e);
                });
    }

    /**
     * Validate new password against policy
     */
    private Mono<String> validatePassword(String password) {
        Instant validationTime = clock.instant();

        log.debug("Validating password policy at {}", validationTime);

        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setPassword(password);

        return passwordPolicyService.validatePassword(dto)
                .thenReturn(password) // ✅ return the original password after successful validation
                .doOnSuccess(validPassword -> {
                    Instant validationEnd = clock.instant();
                    Duration duration = Duration.between(validationTime, validationEnd);

                    log.debug("✅ Password validated at {} in {}", validationEnd, duration);
                })
                .onErrorMap(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Password validation failed at {}: {}", errorTime, e.getMessage());
                    return new IllegalArgumentException("Password does not meet security requirements");
                });
    }


    /**
     * Process password reset
     */
    private Mono<User> processPasswordReset(String token, String newPassword, Instant resetTime, String ipAddress) {
        return tokenService.getEmailFromToken(token)
                .switchIfEmpty(Mono.defer(() -> {
                    Instant errorTime = clock.instant();
                    log.warn("Invalid or expired token at {}", errorTime);
                    return Mono.error(new InvalidTokenException("Invalid or expired reset token"));
                }))
                .flatMap(email -> {
                    log.debug("Retrieved email from token at {}: {}",
                            clock.instant(), HelperUtils.maskEmail(email));
                    return findUserByEmail(email);
                })
                .flatMap(user -> updateUserPassword(user, newPassword, resetTime))
                .flatMap(user -> invalidateToken(token, user))
                // Reuses PasswordChangedListener — same notification email and
                // audit trail as a self-service change via PasswordChangeService.
                // Previously this was the missing step: a reset silently updated
                // the password with no notification to the user at all.
                .flatMap(user -> publishPasswordChangeEvent(user, ipAddress))
                .doOnSuccess(user -> {
                    Instant completionTime = clock.instant();
                    log.info("Password updated and token invalidated at {} for: {}",
                            completionTime, HelperUtils.maskEmail(user.getEmail()));
                });
    }
    /**
     * Publish PasswordChangedEvent so PasswordChangedListener sends the
     * standard "password changed" notification email and audit log entry —
     * same listener PasswordChangeService.changePassword()/forcePasswordChange()
     * already use. `forced=false` since this is user-initiated (via a valid
     * emailed token), not an admin action.
     */
    private Mono<User> publishPasswordChangeEvent(User user, String ipAddress) {
        Instant publishStart = clock.instant();

        return Mono.fromRunnable(() -> {
                    eventPublisherService.publishPasswordChanged(user, ipAddress, false);

                    Instant publishEnd = clock.instant();
                    Duration duration = Duration.between(publishStart, publishEnd);

                    log.debug("✅ Password change event published at {} in {}", publishEnd, duration);
                })
                .thenReturn(user)
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.warn("⚠️ Event publishing failed at {} (non-critical): {}",
                            errorTime, e.getMessage());
                    return Mono.just(user); // Don't fail the reset over a notification hiccup
                });
    }

    /**
     * Update user password
     */
    private Mono<User> updateUserPassword(User user, String newPassword, Instant resetTime) {
        Instant updateTime = clock.instant();

        log.info("Updating password at {} for: {}",
                updateTime, HelperUtils.maskEmail(user.getEmail()));

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        user.setForcePasswordChange(false);
        user.setPasswordLastChanged(updateTime);
        user.setPasswordExpiresAt(updateTime.plus(Duration.ofDays(90))); // 90-day expiry

        // Must update Firebase Auth's own password record — that's what
        // FirebaseAuthValidator actually checks at login. Updating only the
        // Firestore-mirrored hash leaves the real login credential unchanged.
        return firebaseServiceAuth.updateFirebaseAuthPassword(user.getId(), newPassword)
                .then(firebaseServiceAuth.save(user))
                .doOnSuccess(savedUser -> {
                    Instant savedTime = clock.instant();
                    Duration duration = Duration.between(updateTime, savedTime);

                    log.info("✅ Password updated at {} in {} for: {}",
                            savedTime, duration, HelperUtils.maskEmail(user.getEmail()));
                })
                .onErrorMap(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to update password at {} for {}: {}",
                            errorTime, HelperUtils.maskEmail(user.getEmail()), e.getMessage());
                    return new PasswordUpdateException("Failed to update password", e);
                });
    }

    /**
     * Invalidate reset token after successful password reset
     */
    private Mono<User> invalidateToken(String token, User user) {
        Instant invalidationTime = clock.instant();

        log.debug("Invalidating reset token at {} for: {}",
                invalidationTime, HelperUtils.maskEmail(user.getEmail()));

        return tokenService.deleteToken(token)
                .doOnSuccess(deleted -> {
                    Instant deletionTime = clock.instant();
                    Duration duration = Duration.between(invalidationTime, deletionTime);

                    log.info("✅ Reset token invalidated at {} in {}", deletionTime, duration);
                })
                .thenReturn(user)
                .onErrorMap(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to invalidate token at {}: {}", errorTime, e.getMessage());
                    return new TokenInvalidationException("Failed to invalidate reset token", e);
                });
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Determine if error is recoverable for retry
     */
    private boolean isRecoverableError(Throwable e) {
        boolean recoverable = e instanceof EmailSendingException ||
                e instanceof RedisConnectionFailureException;

        if (recoverable) {
            log.debug("Recoverable error detected at {}: {}",
                    clock.instant(), e.getClass().getSimpleName());
        }

        return recoverable;
    }
}