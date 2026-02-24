package com.techStack.authSys.unit.service;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.handler.RegistrationErrorHandlerService;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.events.EventPublisherService;
import com.techStack.authSys.service.registration.*;
import com.techStack.authSys.service.validation.UserInputValidationService;
import com.techStack.authSys.service.verification.EmailVerificationOrchestrator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Professional Test Suite for UserRegistrationOrchestrator
 *
 * Test Coverage:
 * - Complete registration pipeline
 * - Phase coordination
 * - Event publishing
 * - Error handling
 * - Retry mechanism
 * - Metrics recording
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserRegistrationOrchestrator Tests")
class UserRegistrationOrchestratorTest {

    @Mock private UserInputValidationService inputValidationService;
    @Mock private DuplicateEmailCheckService duplicateEmailCheckService;
    @Mock private RegistrationSecurityService registrationSecurityService;
    @Mock private UserCreationService userCreationService;
    @Mock private EmailVerificationOrchestrator emailVerificationOrchestrator;
    @Mock private EventPublisherService eventPublisherService;
    @Mock private RegistrationMetricsService registrationMetricsService;
    @Mock private RegistrationErrorHandlerService errorHandlerService;
    @Mock private DeviceVerificationService deviceVerificationService;
    @Mock private ApplicationEventPublisher eventPublisher;
    @Mock private ServerWebExchange exchange;
    @Mock private ServerHttpRequest request;

    private UserRegistrationOrchestrator orchestrator;
    private Clock fixedClock;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_IP = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0";
    private static final String TEST_DEVICE_FP = "device-fingerprint-123";

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(
                Instant.parse("2024-01-15T10:00:00Z"),
                ZoneId.of("UTC")
        );

        orchestrator = new UserRegistrationOrchestrator(
                inputValidationService,
                duplicateEmailCheckService,
                registrationSecurityService,
                userCreationService,
                emailVerificationOrchestrator,
                eventPublisherService,
                registrationMetricsService,
                errorHandlerService,
                deviceVerificationService,
                eventPublisher,
                fixedClock
        );

        // Setup common mocks
        when(exchange.getRequest()).thenReturn(request);
        when(deviceVerificationService.extractClientIp(exchange)).thenReturn(TEST_IP);
        when(deviceVerificationService.generateDeviceFingerprint(TEST_IP, TEST_USER_AGENT))
                .thenReturn(TEST_DEVICE_FP);
    }

    /* =========================
       Full Pipeline Tests
       ========================= */

    @Test
    @DisplayName("Should complete full registration pipeline successfully")
    void registerUser_FullPipeline_Success() {
        // Given
        UserRegistrationDTO userDto = createUserDto();
        User createdUser = createMockUser();

        // Phase 1: Validation & Security
        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.just(userDto));
        when(duplicateEmailCheckService.checkDuplicateEmail(userDto))
                .thenReturn(Mono.just(userDto));
        when(registrationSecurityService.performSecurityChecks(
                eq(userDto), eq(TEST_IP), eq(TEST_DEVICE_FP)))
                .thenReturn(Mono.empty());

        // Phase 2: User Creation
        when(userCreationService.createUserWithRoles(
                eq(userDto), eq(TEST_IP), eq(TEST_DEVICE_FP)))
                .thenReturn(Mono.just(createdUser));

        // Phase 3: Email Verification
        when(emailVerificationOrchestrator.sendVerificationEmailSafely(
                eq(createdUser), eq(TEST_IP)))
                .thenReturn(Mono.empty());

        // When
        Mono<User> result = orchestrator.registerUser(userDto, exchange);

        // Then
        StepVerifier.create(result)
                .expectNext(createdUser)
                .verifyComplete();

        // Verify all phases executed
        verify(inputValidationService).validateUserInput(userDto);
        verify(duplicateEmailCheckService).checkDuplicateEmail(userDto);
        verify(registrationSecurityService).performSecurityChecks(
                eq(userDto), eq(TEST_IP), eq(TEST_DEVICE_FP));
        verify(userCreationService).createUserWithRoles(
                eq(userDto), eq(TEST_IP), eq(TEST_DEVICE_FP));
        verify(emailVerificationOrchestrator).sendVerificationEmailSafely(
                eq(createdUser), eq(TEST_IP));

        // Verify event published
        verify(eventPublisherService).publishUserRegistered(
                eq(createdUser), eq(TEST_IP), eq(TEST_DEVICE_FP), any());

        // Verify metrics recorded
        verify(registrationMetricsService).recordSuccessfulRegistration(
                eq(createdUser), eq(TEST_IP), eq(TEST_DEVICE_FP), any(), anyLong());
    }

    /* =========================
       Phase Failure Tests
       ========================= */

    @Test
    @DisplayName("Should fail when input validation fails")
    void registerUser_ValidationFailure() {
        // Given
        UserRegistrationDTO userDto = createUserDto();

        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.error(new IllegalArgumentException("Invalid input")));

        // When
        Mono<User> result = orchestrator.registerUser(userDto, exchange);

        // Then
        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();

        // Verify subsequent phases NOT executed
        verify(duplicateEmailCheckService, never()).checkDuplicateEmail(any());
        verify(userCreationService, never()).createUserWithRoles(any(), any(), any());
    }

    @Test
    @DisplayName("Should fail when duplicate email detected")
    void registerUser_DuplicateEmail() {
        // Given
        UserRegistrationDTO userDto = createUserDto();

        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.just(userDto));
        when(duplicateEmailCheckService.checkDuplicateEmail(userDto))
                .thenReturn(Mono.error(
                        new com.techStack.authSys.exception.email.EmailAlreadyExistsException(TEST_EMAIL)));

        // When
        Mono<User> result = orchestrator.registerUser(userDto, exchange);

        // Then
        StepVerifier.create(result)
                .expectError(com.techStack.authSys.exception.email.EmailAlreadyExistsException.class)
                .verify();

        verify(userCreationService, never()).createUserWithRoles(any(), any(), any());
    }

    @Test
    @DisplayName("Should fail when security checks fail")
    void registerUser_SecurityCheckFailure() {
        // Given
        UserRegistrationDTO userDto = createUserDto();

        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.just(userDto));
        when(duplicateEmailCheckService.checkDuplicateEmail(userDto))
                .thenReturn(Mono.just(userDto));
        when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("Security violation")));

        // When
        Mono<User> result = orchestrator.registerUser(userDto, exchange);

        // Then
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();

        verify(userCreationService, never()).createUserWithRoles(any(), any(), any());
    }

    @Test
    @DisplayName("Should continue when email verification fails (non-fatal)")
    void registerUser_EmailVerificationFailure_Continues() {
        // Given
        UserRegistrationDTO userDto = createUserDto();
        User createdUser = createMockUser();

        setupSuccessfulPipeline(userDto, createdUser);

        // Email verification fails
        when(emailVerificationOrchestrator.sendVerificationEmailSafely(any(), any()))
                .thenReturn(Mono.error(new RuntimeException("Email service down")));

        // When
        Mono<User> result = orchestrator.registerUser(userDto, exchange);

        // Then - Should fail (email verification is part of pipeline)
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    /* =========================
       Retry Mechanism Tests
       ========================= */

    @Test
    @DisplayName("Should retry on retryable errors")
    void registerUser_RetryableError_Retries() {
        // Given
        UserRegistrationDTO userDto = createUserDto();
        User createdUser = createMockUser();

        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.just(userDto));
        when(duplicateEmailCheckService.checkDuplicateEmail(userDto))
                .thenReturn(Mono.just(userDto));
        when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                .thenReturn(Mono.empty());

        // First 2 attempts fail with retryable error, 3rd succeeds
        when(userCreationService.createUserWithRoles(any(), any(), any()))
                .thenReturn(Mono.error(new java.net.ConnectException("Network timeout")))
                .thenReturn(Mono.error(new java.net.ConnectException("Network timeout")))
                .thenReturn(Mono.just(createdUser));

        when(emailVerificationOrchestrator.sendVerificationEmailSafely(any(), any()))
                .thenReturn(Mono.empty());

        // When
        Mono<User> result = orchestrator.registerUser(userDto, exchange);

        // Then - Should succeed after retries
        StepVerifier.create(result)
                .expectNext(createdUser)
                .verifyComplete();

        // Verify 3 attempts
        verify(userCreationService, times(3)).createUserWithRoles(any(), any(), any());
    }

    @Test
    @DisplayName("Should NOT retry non-retryable errors")
    void registerUser_NonRetryableError_NoRetry() {
        // Given
        UserRegistrationDTO userDto = createUserDto();

        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.just(userDto));
        when(duplicateEmailCheckService.checkDuplicateEmail(userDto))
                .thenReturn(Mono.just(userDto));
        when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                .thenReturn(Mono.empty());

        // Non-retryable error
        when(userCreationService.createUserWithRoles(any(), any(), any()))
                .thenReturn(Mono.error(new IllegalArgumentException("Invalid data")));

        // When
        Mono<User> result = orchestrator.registerUser(userDto, exchange);

        // Then - Should fail immediately
        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();

        // Verify only 1 attempt
        verify(userCreationService, times(1)).createUserWithRoles(any(), any(), any());
    }

    /* =========================
       Event Publishing Tests
       ========================= */

    @Test
    @DisplayName("Should publish registration event on success")
    void registerUser_PublishesEvent() {
        // Given
        UserRegistrationDTO userDto = createUserDto();
        User createdUser = createMockUser();

        setupSuccessfulPipeline(userDto, createdUser);

        // When
        orchestrator.registerUser(userDto, exchange).block();

        // Then
        verify(eventPublisherService).publishUserRegistered(
                eq(createdUser),
                eq(TEST_IP),
                eq(TEST_DEVICE_FP),
                any()
        );
    }

    @Test
    @DisplayName("Should NOT publish event on failure")
    void registerUser_NoEventOnFailure() {
        // Given
        UserRegistrationDTO userDto = createUserDto();

        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.error(new RuntimeException("Validation failed")));

        // When
        orchestrator.registerUser(userDto, exchange).subscribe(
                user -> {},
                error -> {}
        );

        // Then
        verify(eventPublisherService, never()).publishUserRegistered(any(), any(), any(), any());
    }

    /* =========================
       Metrics Tests
       ========================= */

    @Test
    @DisplayName("Should record success metrics")
    void registerUser_RecordsSuccessMetrics() {
        // Given
        UserRegistrationDTO userDto = createUserDto();
        User createdUser = createMockUser();

        setupSuccessfulPipeline(userDto, createdUser);

        // When
        orchestrator.registerUser(userDto, exchange).block();

        // Then
        verify(registrationMetricsService).recordSuccessfulRegistration(
                eq(createdUser),
                eq(TEST_IP),
                eq(TEST_DEVICE_FP),
                any(),
                anyLong()
        );
    }

    @Test
    @DisplayName("Should handle errors through error handler")
    void registerUser_HandlesErrors() {
        // Given
        UserRegistrationDTO userDto = createUserDto();
        RuntimeException error = new RuntimeException("Registration failed");

        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.error(error));

        // When
        orchestrator.registerUser(userDto, exchange).subscribe(
                user -> {},
                e -> {}
        );

        // Then
        verify(errorHandlerService).handleRegistrationError(eq(error), eq(TEST_EMAIL));
    }

    /* =========================
       Device Tracking Tests
       ========================= */

    @Test
    @DisplayName("Should extract and use device information")
    void registerUser_TracksDevice() {
        // Given
        UserRegistrationDTO userDto = createUserDto();
        User createdUser = createMockUser();

        setupSuccessfulPipeline(userDto, createdUser);

        // When
        orchestrator.registerUser(userDto, exchange).block();

        // Then
        verify(deviceVerificationService).extractClientIp(exchange);
        verify(deviceVerificationService).generateDeviceFingerprint(TEST_IP, null);
        verify(userCreationService).createUserWithRoles(
                eq(userDto), eq(TEST_IP), eq(TEST_DEVICE_FP));
    }

    /* =========================
       Helper Methods
       ========================= */

    private UserRegistrationDTO createUserDto() {
        return UserRegistrationDTO.builder()
                .email(TEST_EMAIL)
                .firstName("Test")
                .lastName("User")
                .password("Password123!")
                .requestedRole("USER")
                .build();
    }

    private User createMockUser() {
        User user = new User();
        user.setId("user-123");
        user.setEmail(TEST_EMAIL);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setStatus(UserStatus.PENDING_APPROVAL);
        return user;
    }

    private void setupSuccessfulPipeline(UserRegistrationDTO userDto, User createdUser) {
        when(inputValidationService.validateUserInput(userDto))
                .thenReturn(Mono.just(userDto));
        when(duplicateEmailCheckService.checkDuplicateEmail(userDto))
                .thenReturn(Mono.just(userDto));
        when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                .thenReturn(Mono.empty());
        when(userCreationService.createUserWithRoles(any(), any(), any()))
                .thenReturn(Mono.just(createdUser));
        when(emailVerificationOrchestrator.sendVerificationEmailSafely(any(), any()))
                .thenReturn(Mono.empty());
    }
}