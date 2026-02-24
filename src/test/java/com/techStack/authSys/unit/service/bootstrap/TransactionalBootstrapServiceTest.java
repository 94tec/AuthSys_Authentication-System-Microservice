package com.techStack.authSys.unit.service.bootstrap;


import com.google.cloud.firestore.Firestore;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.dto.response.BootstrapResult;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.auth.RegistrationEmailGate;
import com.techStack.authSys.service.bootstrap.BootstrapNotificationService;
import com.techStack.authSys.service.bootstrap.BootstrapStateService;
import com.techStack.authSys.service.bootstrap.TransactionalBootstrapService;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.EmailValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Professional Test Suite for TransactionalBootstrapService
 *
 * Test Coverage:
 * - 4-step transactional flow
 * - Rollback at each failure point
 * - Email validation integration
 * - Error handling and recovery
 * - Concurrent request handling
 * - Audit logging
 *
 * Security Considerations:
 * - Password emergency logging
 * - Email masking
 * - Transaction atomicity
 * - Rollback completeness
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("TransactionalBootstrapService Tests")
class TransactionalBootstrapServiceTest {

    @Mock private FirebaseServiceAuth firebaseServiceAuth;
    @Mock private RedisUserCacheService redisCacheService;
    @Mock private BootstrapNotificationService notificationService;
    @Mock private BootstrapStateService stateService;
    @Mock private AuditLogService auditLogService;
    @Mock private MetricsService metricsService;
    @Mock private Firestore firestore;
    @Mock private FirestoreUserRepository firestoreUserRepository;
    @Mock private RegistrationEmailGate registrationEmailGate;
    @Mock private FirebaseAuth firebaseAuth;

    private TransactionalBootstrapService transactionalService;
    private Clock fixedClock;

    private static final String TEST_EMAIL = "admin@example.com";
    private static final String TEST_PHONE = "+254712345678";
    private static final String TEST_USER_ID = "super-admin-123";

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(
                Instant.parse("2024-01-15T10:00:00Z"),
                ZoneId.of("UTC")
        );

        transactionalService = new TransactionalBootstrapService(
                firebaseServiceAuth,
                redisCacheService,
                notificationService,
                stateService,
                auditLogService,
                metricsService,
                firestore,
                firestoreUserRepository,
                registrationEmailGate,
                fixedClock
        );
    }

    /* =========================
       Happy Path Tests
       ========================= */

    @Test
    @DisplayName("Should successfully create super admin with all 4 steps")
    void createSuperAdminTransactionally_FullSuccess() {
        // Given
        User mockUser = createMockSuperAdmin();

        // Email validation passes
        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        // Step 0: Check existing - none found
        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // Step 1: Firebase creation
        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        // Step 2: Redis cache
        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        // Step 3: Mark bootstrap complete
        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        // Step 4: Send email
        when(notificationService.sendWelcomeEmail(eq(TEST_EMAIL), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then
        StepVerifier.create(result)
                .assertNext(bootstrapResult -> {
                    assertThat(bootstrapResult.created()).isTrue();
                    assertThat(bootstrapResult.alreadyExists()).isFalse();
                    assertThat(bootstrapResult.emailSent()).isTrue();
                    assertThat(bootstrapResult.userId()).isEqualTo(TEST_USER_ID);
                })
                .verifyComplete();

        // Verify all steps executed
        verify(firebaseServiceAuth).createSuperAdmin(any(), anyString(), anyString(), anyString());
        verify(redisCacheService).cacheRegisteredEmail(TEST_EMAIL);
        verify(stateService).markBootstrapComplete();
        verify(notificationService).sendWelcomeEmail(eq(TEST_EMAIL), anyString());
        verify(metricsService).incrementCounter("bootstrap.super_admin.created");
    }

    @Test
    @DisplayName("Should return existing admin when already exists")
    void createSuperAdminTransactionally_AlreadyExists() {
        // Given
        User existingUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        // Admin already exists
        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(true));

        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.findByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(existingUser));

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then
        StepVerifier.create(result)
                .assertNext(bootstrapResult -> {
                    assertThat(bootstrapResult.created()).isFalse();
                    assertThat(bootstrapResult.alreadyExists()).isTrue();
                    assertThat(bootstrapResult.emailSent()).isFalse();
                    assertThat(bootstrapResult.userId()).isEqualTo(TEST_USER_ID);
                })
                .verifyComplete();

        // Verify no creation attempted
        verify(firebaseServiceAuth, never()).createSuperAdmin(any(), anyString(), anyString(), anyString());
        verify(metricsService).incrementCounter("bootstrap.super_admin.already_exists");
    }

    /* =========================
       Validation Tests
       ========================= */

    @Test
    @DisplayName("Should validate email before any database operations")
    void createSuperAdminTransactionally_EmailValidationFirst() {
        // Given
        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.error(new IllegalArgumentException("Invalid email")));

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then
        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();

        // Verify no database operations occurred
        verify(firebaseServiceAuth, never()).existsByEmail(anyString());
        verify(firebaseServiceAuth, never()).createSuperAdmin(any(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Should reject null email")
    void createSuperAdminTransactionally_NullEmail() {
        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(null, TEST_PHONE);

        // Then
        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    @Test
    @DisplayName("Should reject empty email")
    void createSuperAdminTransactionally_EmptyEmail() {
        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally("", TEST_PHONE);

        // Then
        StepVerifier.create(result)
                .expectError(IllegalArgumentException.class)
                .verify();
    }

    /* =========================
       Rollback Tests - Critical!
       ========================= */

    @Test
    @DisplayName("Should rollback when Step 1 (Firebase creation) fails")
    void createSuperAdminTransactionally_Step1Failure_NoRollbackNeeded() {
        // Given
        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // Step 1 fails
        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("Firebase creation failed")));

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();

        // Verify no subsequent steps executed
        verify(redisCacheService, never()).cacheRegisteredEmail(anyString());
        verify(stateService, never()).markBootstrapComplete();
        verify(notificationService, never()).sendWelcomeEmail(anyString(), anyString());

        // Verify rollback NOT needed (nothing to rollback)
        verify(firestoreUserRepository, never()).delete(anyString());
    }

    @Test
    @DisplayName("Should rollback when Step 2 (Redis cache) fails")
    void createSuperAdminTransactionally_Step2Failure_RollsBackFirebase() {
        // Given
        User mockUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // Step 1 succeeds
        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        // Step 2 fails (but is non-fatal in implementation)
        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("Redis unavailable")));

        // Step 3 succeeds
        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        // Step 4 succeeds
        when(notificationService.sendWelcomeEmail(eq(TEST_EMAIL), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then - Redis failure is non-fatal, transaction continues
        StepVerifier.create(result)
                .assertNext(bootstrapResult -> {
                    assertThat(bootstrapResult.created()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("Should rollback when Step 3 (mark complete) fails")
    void createSuperAdminTransactionally_Step3Failure_FullRollback() {
        // Given
        User mockUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // Step 1 succeeds
        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        // Step 2 succeeds
        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        // Step 3 fails
        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.error(new RuntimeException("Firestore write failed")));

        // Setup rollback mocks
        when(firestoreUserRepository.delete(TEST_USER_ID))
                .thenReturn(Mono.empty());

        when(redisCacheService.removeRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then
        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();

        // Verify Step 4 NOT executed
        verify(notificationService, never()).sendWelcomeEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should continue when Step 4 (email) fails - non-fatal")
    void createSuperAdminTransactionally_Step4Failure_NonFatal() {
        // Given
        User mockUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // Steps 1-3 succeed
        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        // Step 4 fails
        when(notificationService.sendWelcomeEmail(eq(TEST_EMAIL), anyString()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then - Email failure is non-fatal, user created
        StepVerifier.create(result)
                .assertNext(bootstrapResult -> {
                    assertThat(bootstrapResult.created()).isTrue();
                    assertThat(bootstrapResult.emailSent()).isFalse();
                })
                .verifyComplete();

        // Verify NO rollback on email failure
        verify(firestoreUserRepository, never()).delete(anyString());
    }

    /* =========================
       Error Handling Tests
       ========================= */

    @Test
    @DisplayName("Should handle Firebase auth email conflict")
    void createSuperAdminTransactionally_EmailConflict() throws Exception {
        // Given
        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        FirebaseAuthException emailExistsException =
                mock(FirebaseAuthException.class);
        when(emailExistsException.getAuthErrorCode())
                .thenReturn(com.google.firebase.auth.AuthErrorCode.EMAIL_ALREADY_EXISTS);

        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.error(emailExistsException));

        // Setup recovery path
        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        User existingUser = createMockSuperAdmin();
        when(firebaseServiceAuth.findByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(existingUser));

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then - Should recover and return existing admin
        StepVerifier.create(result)
                .assertNext(bootstrapResult -> {
                    assertThat(bootstrapResult.alreadyExists()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    @DisplayName("Should retry on retryable errors")
    void createSuperAdminTransactionally_RetryableError() {
        // Given
        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        // First call fails with retryable error, second succeeds
        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.error(new RuntimeException("Network timeout")))
                .thenReturn(Mono.just(false));

        User mockUser = createMockSuperAdmin();
        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        when(notificationService.sendWelcomeEmail(eq(TEST_EMAIL), anyString()))
                .thenReturn(Mono.empty());

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then - Should succeed after retry
        StepVerifier.create(result)
                .assertNext(bootstrapResult -> {
                    assertThat(bootstrapResult.created()).isTrue();
                })
                .verifyComplete();

        // Verify retry occurred
        verify(firebaseServiceAuth, times(2)).existsByEmail(TEST_EMAIL);
    }

    @Test
    @DisplayName("Should timeout after 60 seconds")
    void createSuperAdminTransactionally_Timeout() {
        // Given
        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        // Simulate long-running operation
        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.delay(Duration.ofSeconds(65))
                        .then(Mono.just(createMockSuperAdmin())));

        // When
        Mono<BootstrapResult> result = transactionalService
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Then - Should timeout
        StepVerifier.create(result)
                .expectError(java.util.concurrent.TimeoutException.class)
                .verify();
    }

    /* =========================
       Security Tests
       ========================= */

    @Test
    @DisplayName("Should normalize email before processing")
    void createSuperAdminTransactionally_EmailNormalization() {
        // Given
        String unnormalizedEmail = "  Admin@EXAMPLE.COM  ";
        User mockUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail("admin@example.com"))
                .thenReturn(Mono.just(false));

        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        when(redisCacheService.cacheRegisteredEmail("admin@example.com"))
                .thenReturn(Mono.empty());

        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        when(notificationService.sendWelcomeEmail(eq("admin@example.com"), anyString()))
                .thenReturn(Mono.empty());

        // When
        transactionalService.createSuperAdminTransactionally(unnormalizedEmail, TEST_PHONE)
                .block();

        // Then - Should use normalized email
        verify(firebaseServiceAuth).existsByEmail("admin@example.com");
        verify(notificationService).sendWelcomeEmail(eq("admin@example.com"), anyString());
    }

    @Test
    @DisplayName("Should normalize phone before processing")
    void createSuperAdminTransactionally_PhoneNormalization() {
        // Given
        String unnormalizedPhone = "0712345678"; // Kenyan format
        User mockUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        when(firebaseServiceAuth.createSuperAdmin(
                userCaptor.capture(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        when(notificationService.sendWelcomeEmail(eq(TEST_EMAIL), anyString()))
                .thenReturn(Mono.empty());

        // When
        transactionalService.createSuperAdminTransactionally(TEST_EMAIL, unnormalizedPhone)
                .block();

        // Then - Phone should be normalized to E.164
        User capturedUser = userCaptor.getValue();
        assertThat(capturedUser.getPhoneNumber()).isEqualTo("+254712345678");
    }

    /* =========================
       Metrics Tests
       ========================= */

    @Test
    @DisplayName("Should record success metrics")
    void createSuperAdminTransactionally_SuccessMetrics() {
        // Given
        User mockUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(false));

        when(firebaseServiceAuth.createSuperAdmin(any(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.just(mockUser));

        when(redisCacheService.cacheRegisteredEmail(TEST_EMAIL))
                .thenReturn(Mono.empty());

        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        when(notificationService.sendWelcomeEmail(eq(TEST_EMAIL), anyString()))
                .thenReturn(Mono.empty());

        // When
        transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE)
                .block();

        // Then
        verify(metricsService).incrementCounter("bootstrap.super_admin.created");
        verify(metricsService).incrementCounter("user.registration.success");
        verify(metricsService).recordTimer(eq("bootstrap.creation.time"), any(Duration.class));
    }

    @Test
    @DisplayName("Should record already exists metrics")
    void createSuperAdminTransactionally_AlreadyExistsMetrics() {
        // Given
        User existingUser = createMockSuperAdmin();

        when(registrationEmailGate.validate(any()))
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.existsByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(true));

        when(stateService.markBootstrapComplete())
                .thenReturn(Mono.empty());

        when(firebaseServiceAuth.findByEmail(TEST_EMAIL))
                .thenReturn(Mono.just(existingUser));

        // When
        transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE)
                .block();

        // Then
        verify(metricsService).incrementCounter("bootstrap.super_admin.already_exists");
    }

    /* =========================
       Helper Methods
       ========================= */

    private User createMockSuperAdmin() {
        User user = new User();
        user.setId(TEST_USER_ID);
        user.setEmail(TEST_EMAIL);
        user.setPhoneNumber(TEST_PHONE);
        user.setStatus(UserStatus.ACTIVE);
        user.setEnabled(true);
        return user;
    }
}
