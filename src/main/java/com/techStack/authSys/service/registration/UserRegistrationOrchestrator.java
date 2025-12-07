package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.event.UserRegisteredEvent;
import com.techStack.authSys.exception.ServiceUnavailableException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.*;
import com.techStack.authSys.service.verification.EmailVerificationOrchestrator;
import com.techStack.authSys.util.RetryUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;

/**
 * Orchestrates the user registration workflow.
 * Delegates to specialized services for each step.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserRegistrationOrchestrator {

    private final UserInputValidationService inputValidationService;
    private final DuplicateEmailCheckService duplicateEmailCheckService;
    private final RegistrationSecurityService registrationSecurityService;
    private final UserCreationService userCreationService;
    private final EmailVerificationOrchestrator emailVerificationOrchestrator;
    private final RegistrationMetricsService registrationMetricsService;
    private final RegistrationErrorHandlerService errorHandlerService;
    private final DeviceVerificationService deviceVerificationService;
    private final ApplicationEventPublisher eventPublisher;
    private final RetryUtils retryUtils;

    /**
     * Main registration entry point.
     * Coordinates all registration steps in a reactive pipeline.
     */
    public Mono<User> registerUser(UserDTO userDto, ServerWebExchange exchange) {
        long startTime = System.currentTimeMillis();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress,
                userDto.getUserAgent()
        );

        log.info("Registration attempt for email: {} from IP: {}", userDto.getEmail(), ipAddress);

        return Mono.just(userDto)
                // Phase 1: Input Validation & Security Checks
                .flatMap(inputValidationService::validateUserInput)
                .flatMap(duplicateEmailCheckService::checkDuplicateEmail)
                .flatMap(dto -> registrationSecurityService.performSecurityChecks(dto, ipAddress)
                        .thenReturn(dto))

                // Phase 2: User Creation & Role Assignment
                .flatMap(dto -> userCreationService.createUserWithRoles(dto, ipAddress, deviceFingerprint))

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

    private void handleSuccessfulRegistration(
            User user, long startTime, String ipAddress, String deviceFingerprint) {

        long duration = System.currentTimeMillis() - startTime;

        log.info("✅ Registration completed for {} in {} ms (Status: {}, Permissions: {})",
                user.getEmail(), duration, user.getStatus(),
                user.getPermissions() != null ? user.getPermissions().size() : 0);

        // Publish event for other subsystems
        eventPublisher.publishEvent(new UserRegisteredEvent(user, ipAddress));

        // Record metrics
        registrationMetricsService.recordSuccessfulRegistration(
                user, ipAddress, deviceFingerprint, duration);
    }

    private void handleRegistrationError(Throwable e, String email, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        log.error("❌ Registration failed for {} after {} ms", email, duration, e);
        errorHandlerService.handleRegistrationError(e, email);
    }

    private Retry buildRetryPolicy() {
        return Retry.backoff(3, Duration.ofMillis(200))
                .filter(retryUtils::isRetryableError)
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
}

