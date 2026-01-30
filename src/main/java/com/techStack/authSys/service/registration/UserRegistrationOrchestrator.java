package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.event.UserRegisteredEvent;
import com.techStack.authSys.exception.service.ServiceUnavailableException;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.verification.EmailVerificationOrchestrator;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * User Registration Orchestrator
 *
 * Coordinates the complete user registration workflow.
 * Delegates to specialized services for each step.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserRegistrationOrchestrator {

    /* =========================
       Dependencies
       ========================= */

    private final UserInputValidationService inputValidationService;
    private final DuplicateEmailCheckService duplicateEmailCheckService;
    private final RegistrationSecurityService registrationSecurityService;
    private final UserCreationService userCreationService;
    private final EmailVerificationOrchestrator emailVerificationOrchestrator;
    private final RegistrationMetricsService registrationMetricsService;
    private final RegistrationErrorHandlerService errorHandlerService;
    private final DeviceVerificationService deviceVerificationService;
    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    /* =========================
       Main Registration Entry Point
       ========================= */

    /**
     * Main registration entry point.
     * Coordinates all registration steps in a reactive pipeline.
     */
    public Mono<User> registerUser(UserRegistrationDTO userDto, ServerWebExchange exchange) {
        Instant startTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String userAgent = extractUserAgent(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress,
                userAgent
        );

        log.info("📝 Registration attempt for email: {} from IP: {}",
                userDto.getEmail(), ipAddress);

        return Mono.just(userDto)
                // Phase 1: Input Validation & Security Checks
                .flatMap(inputValidationService::validateUserInput)
                .flatMap(duplicateEmailCheckService::checkDuplicateEmail)
                .flatMap(dto -> registrationSecurityService.performSecurityChecks(
                                dto, ipAddress, deviceFingerprint)
                        .thenReturn(dto))

                // Phase 2: User Creation & Role Assignment
                .flatMap(dto -> userCreationService.createUserWithRoles(
                        dto, ipAddress, deviceFingerprint))

                // Phase 3: Post-Registration Tasks (non-blocking where possible)
                .flatMap(user -> emailVerificationOrchestrator
                        .sendVerificationEmailSafely(user, ipAddress)
                        .thenReturn(user))

                // Phase 4: Success Handling
                .doOnSuccess(user -> handleSuccessfulRegistration(
                        user, startTime, ipAddress, deviceFingerprint))

                // Phase 5: Error Handling
                .doOnError(e -> handleRegistrationError(e, userDto.getEmail(), startTime))

                // Phase 6: Retry Policy
                .retryWhen(buildRetryPolicy());
    }

    /* =========================
       Success & Error Handlers
       ========================= */

    /**
     * Handle successful registration
     */
    private void handleSuccessfulRegistration(
            User user,
            Instant startTime,
            String ipAddress,
            String deviceFingerprint
    ) {
        Instant now = clock.instant();
        long duration = Duration.between(startTime, now).toMillis();

        log.info("✅ Registration completed for {} in {} ms (Status: {}, Roles: {})",
                user.getEmail(), duration, user.getStatus(),
                user.getRoleNames() != null ? user.getRoleNames().size() : 0);

        // Publish event for other subsystems
        eventPublisher.publishEvent(new UserRegisteredEvent(user, ipAddress));

        // Record metrics
        registrationMetricsService.recordSuccessfulRegistration(
                user, ipAddress, deviceFingerprint, duration);
    }

    /**
     * Handle registration error
     */
    private void handleRegistrationError(Throwable e, String email, Instant startTime) {
        Instant now = clock.instant();
        long duration = Duration.between(startTime, now).toMillis();

        log.error("❌ Registration failed for {} after {} ms: {}",
                email, duration, e.getMessage());

        errorHandlerService.handleRegistrationError(e, email);
    }

    /* =========================
       Retry Policy
       ========================= */

    /**
     * Build retry policy for transient failures
     */
    private Retry buildRetryPolicy() {
        return Retry.backoff(3, Duration.ofMillis(200))
                .filter(HelperUtils::isRetryableError)
                .doBeforeRetry(retrySignal ->
                        log.info("🔄 Retrying registration attempt #{}",
                                retrySignal.totalRetriesInARow() + 1))
                .onRetryExhaustedThrow((retrySpec, retrySignal) -> {
                    Throwable lastFailure = retrySignal.failure();
                    log.error("❌ Max retries exhausted. Last failure: {}",
                            lastFailure.getMessage());
                    return new ServiceUnavailableException("Registration service");
                });
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Extract user agent from exchange
     */
    private String extractUserAgent(ServerWebExchange exchange) {
        return exchange.getRequest()
                .getHeaders()
                .getFirst("User-Agent");
    }
}