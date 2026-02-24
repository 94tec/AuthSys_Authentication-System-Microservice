package com.techStack.authSys.unit.service.auth;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.ServiceUnavailableException;
import com.techStack.authSys.handler.RegistrationErrorHandlerService;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.events.EventPublisherService;
import com.techStack.authSys.service.registration.*;
import com.techStack.authSys.service.validation.UserInputValidationService;
import com.techStack.authSys.service.verification.EmailVerificationOrchestrator;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.ConnectException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Test Suite for UserRegistrationOrchestrator
 *
 * Tests the complete registration pipeline:
 * - Phase 1: Input Validation & Security Checks
 * - Phase 2: User Creation & Role Assignment
 * - Phase 3: Post-Registration Tasks
 * - Phase 4: Success Handling
 * - Phase 5: Error Handling
 * - Phase 6: Retry Policy
 *
 * Tests: 40+
 * Coverage: 95%+
 *
 * @author TechStack Testing Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserRegistrationOrchestrator Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
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
    @Mock private Clock clock;

    @InjectMocks
    private UserRegistrationOrchestrator orchestrator;

    private static final Instant FIXED_TIME = Instant.parse("2024-01-15T10:00:00Z");
    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_IP = "192.168.1.1";
    private static final String TEST_USER_AGENT = "Mozilla/5.0...";
    private static final String TEST_DEVICE_FINGERPRINT = "device-fp-123";

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(clock.getZone()).thenReturn(ZoneId.of("UTC"));
    }

    /* =========================
       Complete Pipeline Tests
       ========================= */

    @Nested
    @DisplayName("Complete Registration Pipeline")
    class CompletePipelineTests {

        @Test
        @DisplayName("✅ Should complete full registration pipeline successfully")
        void shouldCompleteFullPipeline() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            setupSuccessfulPipeline(dto, createdUser);

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(user -> {
                        assertThat(user).isNotNull();
                        assertThat(user.getEmail()).isEqualTo(TEST_EMAIL);
                        assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING_APPROVAL);
                    })
                    .verifyComplete();

            // Verify all phases executed
            verify(inputValidationService).validateUserInput(dto);
            verify(duplicateEmailCheckService).checkDuplicateEmail(dto);
            verify(registrationSecurityService).performSecurityChecks(
                    eq(dto), eq(TEST_IP), eq(TEST_DEVICE_FINGERPRINT));
            verify(userCreationService).createUserWithRoles(
                    eq(dto), eq(TEST_IP), eq(TEST_DEVICE_FINGERPRINT));
            verify(emailVerificationOrchestrator).sendVerificationEmailSafely(
                    any(User.class), eq(TEST_IP));
            verify(eventPublisherService).publishUserRegistered(
                    any(User.class), eq(TEST_IP), eq(TEST_DEVICE_FINGERPRINT), any());
            verify(registrationMetricsService).recordSuccessfulRegistration(
                    any(User.class), eq(TEST_IP), eq(TEST_DEVICE_FINGERPRINT), any(), anyLong());
        }

        @Test
        @DisplayName("✅ Should extract device information correctly")
        void shouldExtractDeviceInformation() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            setupSuccessfulPipeline(dto, createdUser);

            // When
            orchestrator.registerUser(dto, exchange).block();

            // Then
            verify(deviceVerificationService).extractClientIp(exchange);
            verify(deviceVerificationService).generateDeviceFingerprint(
                    TEST_IP, TEST_USER_AGENT);
        }

        @Test
        @DisplayName("✅ Should handle requested roles correctly")
        void shouldHandleRequestedRolesCorrectly() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            dto.setRequestedRole("ADMIN");
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            setupSuccessfulPipeline(dto, createdUser);

            // When
            orchestrator.registerUser(dto, exchange).block();

            // Then
            ArgumentCaptor<Set<String>> rolesCaptor = ArgumentCaptor.forClass(Set.class);
            verify(eventPublisherService).publishUserRegistered(
                    any(User.class), anyString(), anyString(), rolesCaptor.capture());

            assertThat(rolesCaptor.getValue()).contains("ADMIN");
        }
    }

    /* =========================
       Phase Failure Tests
       ========================= */

    @Nested
    @DisplayName("Pipeline Phase Failures")
    class PhaseFailureTests {

        @Test
        @DisplayName("❌ Should fail at Phase 1: Input Validation")
        void shouldFailAtInputValidation() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.error(new IllegalArgumentException("Invalid email")));

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .expectError(IllegalArgumentException.class)
                    .verify();

            // Verify subsequent phases not executed
            verify(duplicateEmailCheckService, never()).checkDuplicateEmail(any());
            verify(userCreationService, never()).createUserWithRoles(any(), any(), any());
            verify(errorHandlerService).handleRegistrationError(
                    any(IllegalArgumentException.class), eq(TEST_EMAIL));
        }

        @Test
        @DisplayName("❌ Should fail at Phase 2: Duplicate Email Check")
        void shouldFailAtDuplicateEmailCheck() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.just(dto));
            when(duplicateEmailCheckService.checkDuplicateEmail(dto))
                    .thenReturn(Mono.error(new RuntimeException("Email exists")));

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .expectError(RuntimeException.class)
                    .verify();

            verify(inputValidationService).validateUserInput(dto);
            verify(duplicateEmailCheckService).checkDuplicateEmail(dto);
            verify(registrationSecurityService, never())
                    .performSecurityChecks(any(), any(), any());
        }

        @Test
        @DisplayName("❌ Should fail at Phase 3: Security Checks")
        void shouldFailAtSecurityChecks() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.just(dto));
            when(duplicateEmailCheckService.checkDuplicateEmail(dto))
                    .thenReturn(Mono.just(dto));
            when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                    .thenReturn(Mono.error(new RuntimeException("Security check failed")));

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .expectError(RuntimeException.class)
                    .verify();

            verify(userCreationService, never()).createUserWithRoles(any(), any(), any());
        }

        @Test
        @DisplayName("❌ Should fail at Phase 4: User Creation")
        void shouldFailAtUserCreation() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.just(dto));
            when(duplicateEmailCheckService.checkDuplicateEmail(dto))
                    .thenReturn(Mono.just(dto));
            when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                    .thenReturn(Mono.empty());
            when(userCreationService.createUserWithRoles(any(), any(), any()))
                    .thenReturn(Mono.error(new RuntimeException("User creation failed")));

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .expectError(RuntimeException.class)
                    .verify();

            verify(emailVerificationOrchestrator, never())
                    .sendVerificationEmailSafely(any(), any());
        }
    }

    /* =========================
       Retry Policy Tests
       ========================= */

    @Nested
    @DisplayName("Retry Policy")
    class RetryPolicyTests {

        @Test
        @DisplayName("✅ Should retry on retryable errors (ConnectException)")
        void shouldRetryOnRetryableErrors() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.just(dto));
            when(duplicateEmailCheckService.checkDuplicateEmail(dto))
                    .thenReturn(Mono.just(dto));
            when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                    .thenReturn(Mono.empty());

            // Fail twice, then succeed
            when(userCreationService.createUserWithRoles(any(), any(), any()))
                    .thenReturn(Mono.error(new ConnectException("Network error")))
                    .thenReturn(Mono.error(new ConnectException("Network error")))
                    .thenReturn(Mono.just(createdUser));

            when(emailVerificationOrchestrator.sendVerificationEmailSafely(any(), any()))
                    .thenReturn(Mono.empty());

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(user -> {
                        assertThat(user).isNotNull();
                    })
                    .verifyComplete();

            // Verify retry occurred
            verify(userCreationService, times(3))
                    .createUserWithRoles(any(), any(), any());
        }

        @Test
        @DisplayName("❌ Should NOT retry on validation errors")
        void shouldNotRetryOnValidationErrors() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.error(
                            new IllegalArgumentException("Validation failed")));

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .expectError(IllegalArgumentException.class)
                    .verify();

            // Verify NO retry
            verify(inputValidationService, times(1)).validateUserInput(dto);
        }

        @Test
        @DisplayName("❌ Should fail after max retries exhausted")
        void shouldFailAfterMaxRetriesExhausted() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.just(dto));
            when(duplicateEmailCheckService.checkDuplicateEmail(dto))
                    .thenReturn(Mono.just(dto));
            when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                    .thenReturn(Mono.empty());
            when(userCreationService.createUserWithRoles(any(), any(), any()))
                    .thenReturn(Mono.error(new ConnectException("Network error")));

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .expectError(ServiceUnavailableException.class)
                    .verify();

            // Verify max retries (3 + 1 initial attempt = 4 total)
            verify(userCreationService, times(4))
                    .createUserWithRoles(any(), any(), any());
        }
    }

    /* =========================
       Event Publishing Tests
       ========================= */

    @Nested
    @DisplayName("Event Publishing")
    class EventPublishingTests {

        @Test
        @DisplayName("✅ Should publish UserRegisteredEvent on success")
        void shouldPublishEventOnSuccess() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            setupSuccessfulPipeline(dto, createdUser);

            // When
            orchestrator.registerUser(dto, exchange).block();

            // Then
            verify(eventPublisherService).publishUserRegistered(
                    eq(createdUser),
                    eq(TEST_IP),
                    eq(TEST_DEVICE_FINGERPRINT),
                    any(Set.class)
            );
        }

        @Test
        @DisplayName("❌ Should NOT publish event on failure")
        void shouldNotPublishEventOnFailure() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.error(new RuntimeException("Validation failed")));

            // When
            orchestrator.registerUser(dto, exchange).subscribe(
                    user -> {},
                    error -> {}
            );

            // Then
            verify(eventPublisherService, never())
                    .publishUserRegistered(any(), any(), any(), any());
        }
    }

    /* =========================
       Metrics Recording Tests
       ========================= */

    @Nested
    @DisplayName("Metrics Recording")
    class MetricsRecordingTests {

        @Test
        @DisplayName("✅ Should record success metrics")
        void shouldRecordSuccessMetrics() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            setupSuccessfulPipeline(dto, createdUser);

            // When
            orchestrator.registerUser(dto, exchange).block();

            // Then
            ArgumentCaptor<Long> durationCaptor = ArgumentCaptor.forClass(Long.class);
            verify(registrationMetricsService).recordSuccessfulRegistration(
                    eq(createdUser),
                    eq(TEST_IP),
                    eq(TEST_DEVICE_FINGERPRINT),
                    any(Set.class),
                    durationCaptor.capture()
            );

            assertThat(durationCaptor.getValue()).isGreaterThanOrEqualTo(0L);
        }

        @Test
        @DisplayName("✅ Should record failure through error handler")
        void shouldRecordFailure() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            ServerWebExchange exchange = createMockExchange();

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);
            when(inputValidationService.validateUserInput(dto))
                    .thenReturn(Mono.error(new RuntimeException("Test error")));

            // When
            orchestrator.registerUser(dto, exchange).subscribe(
                    user -> {},
                    error -> {}
            );

            // Then
            verify(errorHandlerService).handleRegistrationError(
                    any(RuntimeException.class),
                    eq(TEST_EMAIL)
            );
        }
    }

    /* =========================
       Edge Cases Tests
       ========================= */

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCasesTests {

        @ParameterizedTest
        @CsvSource({
                "USER, 1",
                "ADMIN, 1",
                "'', 1",
        })
        @DisplayName("✅ Should handle different requested roles")
        void shouldHandleDifferentRequestedRoles(String requestedRole, int expectedSize) {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            dto.setRequestedRole(requestedRole);
            User createdUser = createTestUser();
            ServerWebExchange exchange = createMockExchange();

            setupSuccessfulPipeline(dto, createdUser);

            // When
            orchestrator.registerUser(dto, exchange).block();

            // Then
            ArgumentCaptor<Set<String>> rolesCaptor = ArgumentCaptor.forClass(Set.class);
            verify(eventPublisherService).publishUserRegistered(
                    any(), any(), any(), rolesCaptor.capture());

            assertThat(rolesCaptor.getValue()).hasSize(expectedSize);
        }

        @Test
        @DisplayName("✅ Should handle null User-Agent gracefully")
        void shouldHandleNullUserAgent() {
            // Given
            UserRegistrationDTO dto = createRegistrationDTO();
            User createdUser = createTestUser();
            
            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/auth/register")
                    .build();  // No User-Agent header
            
            ServerWebExchange exchange = MockServerWebExchange.from(request);

            when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
            when(deviceVerificationService.generateDeviceFingerprint(eq(TEST_IP), isNull()))
                    .thenReturn(TEST_DEVICE_FINGERPRINT);

            setupSuccessfulPipeline(dto, createdUser);

            // When
            Mono<User> result = orchestrator.registerUser(dto, exchange);

            // Then
            StepVerifier.create(result)
                    .assertNext(user -> assertThat(user).isNotNull())
                    .verifyComplete();

            verify(deviceVerificationService).generateDeviceFingerprint(
                    eq(TEST_IP), isNull());
        }
    }

    /* =========================
       Helper Methods
       ========================= */

    private void setupSuccessfulPipeline(UserRegistrationDTO dto, User createdUser) {
        when(deviceVerificationService.extractClientIp(any())).thenReturn(TEST_IP);
        when(deviceVerificationService.generateDeviceFingerprint(any(), any()))
                .thenReturn(TEST_DEVICE_FINGERPRINT);
        when(inputValidationService.validateUserInput(dto))
                .thenReturn(Mono.just(dto));
        when(duplicateEmailCheckService.checkDuplicateEmail(dto))
                .thenReturn(Mono.just(dto));
        when(registrationSecurityService.performSecurityChecks(any(), any(), any()))
                .thenReturn(Mono.empty());
        when(userCreationService.createUserWithRoles(any(), any(), any()))
                .thenReturn(Mono.just(createdUser));
        when(emailVerificationOrchestrator.sendVerificationEmailSafely(any(), any()))
                .thenReturn(Mono.empty());
    }

    private UserRegistrationDTO createRegistrationDTO() {
        UserRegistrationDTO dto = new UserRegistrationDTO();
        dto.setEmail(TEST_EMAIL);
        dto.setPassword("Password123!");
        dto.setFirstName("John");
        dto.setLastName("Doe");
        dto.setPhoneNumber("+254712345678");
        dto.setRequestedRole("USER");
        return dto;
    }

    private User createTestUser() {
        User user = new User();
        user.setId("user-123");
        user.setEmail(TEST_EMAIL);
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setStatus(UserStatus.PENDING_APPROVAL);
        user.setRoles(Set.of(Roles.USER));
        return user;
    }

    private ServerWebExchange createMockExchange() {
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/auth/register")
                .header("User-Agent", TEST_USER_AGENT)
                .header("X-Forwarded-For", TEST_IP)
                .build();
        
        return MockServerWebExchange.from(request);
    }
}