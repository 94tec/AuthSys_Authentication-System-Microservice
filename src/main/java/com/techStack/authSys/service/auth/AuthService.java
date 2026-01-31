package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.registration.UserRegistrationOrchestrator;
import com.techStack.authSys.service.verification.EmailVerificationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

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

    /* =========================
       User Registration
       ========================= */

    /**
     * Register a new user account.
     *
     * @param registrationDTO User registration data
     * @param exchange        HTTP exchange containing request metadata
     * @return Newly created user
     */
    public Mono<User> registerUser(
            UserRegistrationDTO registrationDTO,
            ServerWebExchange exchange
    ) {
        log.debug("AuthService: Routing registration request for email: {}",
                registrationDTO.getEmail());

        return registrationOrchestrator.registerUser(registrationDTO, exchange)
                .doOnSuccess(user ->
                        log.debug("AuthService: Registration successful for: {}", user.getEmail())
                )
                .doOnError(e ->
                        log.error("AuthService: Registration failed for: {}",
                                registrationDTO.getEmail(), e)
                );
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
        log.debug("AuthService: Routing email verification request from IP: {}", ipAddress);

        return emailVerificationService.verifyEmail(token, ipAddress)
                .doOnSuccess(v ->
                        log.debug("AuthService: Email verification successful")
                )
                .doOnError(e ->
                        log.error("AuthService: Email verification failed", e)
                );
    }

    /**
     * Resend verification email to user.
     *
     * @param email     User's email address
     * @param ipAddress Client IP address
     * @return Void on success
     */
    public Mono<Void> resendVerificationEmail(String email, String ipAddress) {
        log.debug("AuthService: Routing resend verification email request for: {}", email);

        return emailVerificationService.resendVerificationEmail(email, ipAddress)
                .doOnSuccess(v ->
                        log.debug("AuthService: Verification email resent to: {}", email)
                )
                .doOnError(e ->
                        log.error("AuthService: Failed to resend verification email to: {}", email, e)
                );
    }
}