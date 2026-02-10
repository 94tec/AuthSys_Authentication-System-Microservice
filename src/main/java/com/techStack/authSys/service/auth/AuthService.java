package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.registration.UserRegistrationOrchestrator;
import com.techStack.authSys.service.security.DomainValidationService;
import com.techStack.authSys.service.verification.EmailVerificationService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Auth Service - Facade for Authentication Operations
 *
 * Delegates to specialized services for each operation.
 * Single responsibility: routing requests to appropriate services.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRegistrationOrchestrator registrationOrchestrator;
    private final EmailVerificationService emailVerificationService;
    private final DomainValidationService domainValidationService;
    private final Clock clock;

    /* =========================
       User Registration
       ========================= */

    /**
     * Register a new user account.
     *
     * Validates email FIRST before any user is created.
     *
     * @param registrationDTO User registration data
     * @param exchange        HTTP exchange containing request metadata
     * @return Newly created user
     */
    public Mono<User> registerUser(
            UserRegistrationDTO registrationDTO,
            ServerWebExchange exchange
    ) {
        Instant start = clock.instant();

        log.info("Registration request at {} for: {}",
                start, HelperUtils.maskEmail(registrationDTO.getEmail()));

        return domainValidationService.validateActiveDomain(registrationDTO) // ✅ ADDED
                .then(registrationOrchestrator.registerUser(registrationDTO, exchange))
                .doOnSuccess(user -> {
                    Instant end = clock.instant();
                    Duration duration = Duration.between(start, end);

                    log.info("✅ Registration completed at {} in {} for user: {}",
                            end, duration, user.getId());
                })
                .doOnError(e -> {
                    Instant end = clock.instant();
                    Duration duration = Duration.between(start, end);

                    log.error("❌ Registration failed at {} after {} for: {} - {}",
                            end, duration,
                            HelperUtils.maskEmail(registrationDTO.getEmail()),
                            e.getMessage());
                });
    }

    /* =========================
       Email Verification
       ========================= */

    /**
     * Verify user's email address using verification token.
     *
     * @param token     Email verification token
     * @param ipAddress Client IP address for security validation
     * @return Void on success
     */
    public Mono<Void> verifyEmail(String token, String ipAddress) {
        Instant start = clock.instant();

        log.debug("Email verification attempt at {} from IP: {}",
                start, HelperUtils.maskIpAddress(ipAddress));

        return emailVerificationService.verifyEmail(token, ipAddress)
                .doOnSuccess(v -> {
                    Instant end = clock.instant();
                    Duration duration = Duration.between(start, end);

                    log.info("✅ Email verification successful at {} in {}", end, duration);
                })
                .doOnError(e -> {
                    Instant end = clock.instant();

                    log.error("❌ Email verification failed at {} from IP {}: {}",
                            end, HelperUtils.maskIpAddress(ipAddress), e.getMessage());
                });
    }

    /**
     * Resend verification email to user.
     *
     * @param email     User's email address
     * @param ipAddress Client IP address
     * @return Void on success
     */
    public Mono<Void> resendVerificationEmail(String email, String ipAddress) {
        Instant start = clock.instant();

        log.debug("Resend verification request at {} for: {} from IP: {}",
                start,
                HelperUtils.maskEmail(email),
                HelperUtils.maskIpAddress(ipAddress));

        return emailVerificationService.resendVerificationEmail(email, ipAddress)
                .doOnSuccess(v -> {
                    Instant end = clock.instant();
                    Duration duration = Duration.between(start, end);

                    log.info("✅ Verification email resent at {} in {} to: {}",
                            end, duration, HelperUtils.maskEmail(email));
                })
                .doOnError(e -> {
                    Instant end = clock.instant();

                    log.error("❌ Failed to resend verification email at {} to: {} - {}",
                            end,
                            HelperUtils.maskEmail(email),
                            e.getMessage());
                });
    }
}