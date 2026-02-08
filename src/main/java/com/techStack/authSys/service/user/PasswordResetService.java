package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.auth.InvalidTokenException;
import com.techStack.authSys.exception.auth.TokenGenerationException;
import com.techStack.authSys.exception.auth.TokenInvalidationException;
import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.exception.password.PasswordUpdateException;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.repository.notification.EmailService;
import com.techStack.authSys.service.security.DomainValidationService;
import com.techStack.authSys.service.token.PasswordResetTokenService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
    private final EmailService emailService;
    private final PasswordResetTokenService tokenService;
    private final PasswordPolicyService passwordPolicyService;
    private final DomainValidationService domainValidationService;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${app.password-reset.base-url:https://yourapp.com}")
    private String resetBaseUrl;

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

        return domainValidationService.validateActiveDomain(dto)
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
     * Send password reset email
     */
    private Mono<String> sendResetEmail(String email, String token) {
        Instant emailTime = clock.instant();
        String resetLink = String.format("%s/reset-password?token=%s", resetBaseUrl, token);

        log.debug("Sending reset email at {} to: {}",
                emailTime, HelperUtils.maskEmail(email));

        String subject = "Password Reset Request";
        String body = buildResetEmailBody(resetLink, emailTime);

        return emailService.sendEmail(email, subject, body)
                .doOnSuccess(v -> {
                    Instant sentTime = clock.instant();
                    Duration duration = Duration.between(emailTime, sentTime);

                    log.info("📧 Reset email sent at {} in {} to: {}",
                            sentTime, duration, HelperUtils.maskEmail(email));
                })
                .thenReturn(token)
                .onErrorMap(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to send reset email at {} to {}: {}",
                            errorTime, HelperUtils.maskEmail(email), e.getMessage());
                    return new EmailSendingException("Failed to send password reset email", e);
                });
    }

    /**
     * Build reset email body
     */
    private String buildResetEmailBody(String resetLink, Instant emailTime) {
        Instant expiresAt = emailTime.plus(TOKEN_VALIDITY);

        return String.format("""
            <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>You requested to reset your password. Click the link below to continue:</p>
                <p><a href="%s" style="background-color: #4CAF50; color: white; padding: 14px 20px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a></p>
                <p><b>⏰ This link expires at %s (in 1 hour)</b></p>
                <p>If you didn't request this, please ignore this email and your password will remain unchanged.</p>
                <p><small>Request received at: %s</small></p>
                <hr>
                <p><small>For security reasons, never share this link with anyone.</small></p>
            </body>
            </html>
            """,
                resetLink,
                expiresAt,
                emailTime
        );
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
    public Mono<User> resetPassword(String token, String newPassword) {
        Instant resetTime = clock.instant();

        log.info("Password reset process started at {}", resetTime);

        return validatePassword(newPassword)
                .flatMap(validPassword -> processPasswordReset(token, validPassword, resetTime))
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
    private Mono<User> processPasswordReset(String token, String newPassword, Instant resetTime) {
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
                .doOnSuccess(user -> {
                    Instant completionTime = clock.instant();
                    log.info("Password updated and token invalidated at {} for: {}",
                            completionTime, HelperUtils.maskEmail(user.getEmail()));
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

        return firebaseServiceAuth.save(user)
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