package com.techStack.authSys.unit.service.bootstrap;


import com.techStack.authSys.config.core.AppConfigProperties;
import com.techStack.authSys.dto.response.BootstrapResult;
import com.techStack.authSys.exception.bootstrap.BootstrapInitializationException;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.service.bootstrap.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Professional Test Suite for BootstrapOrchestrator
 *
 * Test Coverage:
 * - Startup orchestration
 * - Configuration validation
 * - Lock coordination
 * - Retry mechanism
 * - Metrics recording
 * - Error handling
 *
 * Security Considerations:
 * - Configuration validation first
 * - Lock prevention of concurrent execution
 * - Proper error propagation
 * - Audit trail completeness
 *
 * @author TechStack Security Team
 * @version 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("BootstrapOrchestrator Tests")
class BootstrapOrchestratorTest {

    @Mock private BootstrapLockService lockService;
    @Mock private BootstrapValidationService validationService;
    @Mock private BootstrapStateService stateService;
    @Mock private TransactionalBootstrapService transactionalService;
    @Mock private MetricsService metricsService;
    @Mock private AppConfigProperties appConfigProperties;

    private BootstrapOrchestrator orchestrator;
    private Clock fixedClock;

    private static final String TEST_EMAIL = "admin@example.com";
    private static final String TEST_PHONE = "+254712345678";

    @BeforeEach
    void setUp() {
        fixedClock = Clock.fixed(
                Instant.parse("2024-01-15T10:00:00Z"),
                ZoneId.of("UTC")
        );

        orchestrator = new BootstrapOrchestrator(
                lockService,
                validationService,
                stateService,
                transactionalService,
                metricsService,
                appConfigProperties,
                fixedClock
        );

        // Default config setup
        when(appConfigProperties.getSuperAdminEmail()).thenReturn(TEST_EMAIL);
        when(appConfigProperties.getSuperAdminPhone()).thenReturn(TEST_PHONE);
    }

    /* =========================
       Configuration Validation Tests
       ========================= */

    @Test
    @DisplayName("Should validate configuration before any operations")
    void run_ValidConfiguration_ProceedsToBootstrap() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(true));

        // When
        orchestrator.run();

        // Then - Should proceed past validation
        verify(lockService).acquireBootstrapLock();
    }

    @Test
    @DisplayName("Should fail immediately on invalid configuration")
    void run_InvalidConfiguration_FailsImmediately() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(false);

        // When/Then
        assertThatThrownBy(() -> orchestrator.run())
                .isInstanceOf(BootstrapInitializationException.class)
                .hasMessageContaining("Bootstrap configuration validation failed");

        // Verify no further operations attempted
        verify(lockService, never()).acquireBootstrapLock();
        verify(metricsService).incrementCounter("bootstrap.config.invalid");
    }

    /* =========================
       Lock Coordination Tests
       ========================= */

    @Test
    @DisplayName("Should execute bootstrap when lock acquired")
    void run_LockAcquired_ExecutesBootstrap() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then
        verify(transactionalService).createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);
        verify(lockService).releaseBootstrapLock();
    }

    @Test
    @DisplayName("Should wait when lock not acquired")
    void run_LockNotAcquired_WaitsForCompletion() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        // Lock not acquired (another instance is bootstrapping)
        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(false));

        when(stateService.waitForBootstrapCompletion())
                .thenReturn(Mono.empty());

        // When
        orchestrator.run();

        // Then - Should wait, not execute
        verify(stateService).waitForBootstrapCompletion();
        verify(transactionalService, never())
                .createSuperAdminTransactionally(anyString(), anyString());
    }

    @Test
    @DisplayName("Should release lock on success")
    void run_Success_ReleasesLock() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then
        verify(lockService).releaseBootstrapLock();
    }

    @Test
    @DisplayName("Should release lock on failure")
    void run_Failure_ReleasesLock() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.error(new RuntimeException("Database error")));

        doNothing().when(lockService).releaseBootstrapLock();

        // When/Then
        assertThatThrownBy(() -> orchestrator.run())
                .isInstanceOf(BootstrapInitializationException.class);

        // Lock still released
        verify(lockService).releaseBootstrapLock();
    }

    /* =========================
       Retry Mechanism Tests
       ========================= */

    @Test
    @DisplayName("Should retry on retryable errors up to 3 times")
    void run_RetryableError_Retries3Times() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        // Fail 3 times, succeed on 4th
        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.error(new RuntimeException("Network timeout")))
                .thenReturn(Mono.error(new RuntimeException("Network timeout")))
                .thenReturn(Mono.error(new RuntimeException("Network timeout")))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then - Should succeed after retries
        verify(transactionalService, times(4))
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);
        verify(metricsService, times(3))
                .incrementCounter("bootstrap.retry.attempt");
    }

    @Test
    @DisplayName("Should fail after max retries exhausted")
    void run_RetryExhausted_ThrowsException() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        // Always fail
        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.error(new RuntimeException("Persistent failure")));

        doNothing().when(lockService).releaseBootstrapLock();

        // When/Then
        assertThatThrownBy(() -> orchestrator.run())
                .isInstanceOf(BootstrapInitializationException.class)
                .hasMessageContaining("Bootstrap failed after 3 retries");

        // Verify max retries attempted
        verify(transactionalService, times(4)) // Initial + 3 retries
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);
    }

    @Test
    @DisplayName("Should not retry non-retryable errors")
    void run_NonRetryableError_FailsImmediately() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        // Non-retryable error
        BootstrapInitializationException nonRetryable =
                new BootstrapInitializationException(
                        "Validation failed",
                        "VALIDATION_ERROR",
                        null,
                        false // isRetryable = false
                );

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.error(nonRetryable));

        doNothing().when(lockService).releaseBootstrapLock();

        // When/Then
        assertThatThrownBy(() -> orchestrator.run())
                .isInstanceOf(BootstrapInitializationException.class);

        // Verify only 1 attempt (no retries)
        verify(transactionalService, times(1))
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);
        verify(metricsService, never())
                .incrementCounter("bootstrap.retry.attempt");
    }

    /* =========================
       Metrics Tests
       ========================= */

    @Test
    @DisplayName("Should record created metrics on success")
    void run_Success_RecordsCreatedMetrics() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then
        verify(metricsService).incrementCounter("bootstrap.super_admin.created");
        verify(metricsService).incrementCounter("bootstrap.completed");
        verify(metricsService).recordTimer(eq("bootstrap.total.time"), any(Duration.class));
    }

    @Test
    @DisplayName("Should record already exists metrics")
    void run_AlreadyExists_RecordsExistingMetrics() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(true));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then
        verify(metricsService).incrementCounter("bootstrap.super_admin.already_exists");
        verify(metricsService).incrementCounter("bootstrap.completed");
    }

    @Test
    @DisplayName("Should record duration timer")
    void run_Success_RecordsDuration() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then
        ArgumentCaptor<Duration> durationCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(metricsService).recordTimer(
                eq("bootstrap.total.time"),
                durationCaptor.capture()
        );

        // Verify reasonable duration
        assertThat(durationCaptor.getValue()).isNotNull();
    }

    /* =========================
       Bootstrap State Tests
       ========================= */

    @Test
    @DisplayName("Should skip execution if already completed")
    void run_AlreadyCompleted_Skips() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        // Already completed
        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(true));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then - Should skip creation
        verify(transactionalService, never())
                .createSuperAdminTransactionally(anyString(), anyString());
        verify(metricsService).incrementCounter("bootstrap.super_admin.already_exists");
    }

    @Test
    @DisplayName("Should execute if not completed")
    void run_NotCompleted_Executes() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then
        verify(transactionalService).createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);
    }

    /* =========================
       Timeout Tests
       ========================= */

    @Test
    @DisplayName("Should timeout after 10 minutes")
    void run_ExceedsTimeout_Fails() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        // Simulate long operation
        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.delay(Duration.ofMinutes(11))
                        .then(Mono.just(BootstrapResult.created("user-123", true))));

        doNothing().when(lockService).releaseBootstrapLock();

        // When/Then
        assertThatThrownBy(() -> orchestrator.run())
                .isInstanceOf(BootstrapInitializationException.class)
                .hasMessageContaining("failed");

        verify(lockService).releaseBootstrapLock();
    }

    /* =========================
       Error Classification Tests
       ========================= */

    @Test
    @DisplayName("Should classify network errors as retryable")
    void isRetryableError_NetworkError_ReturnsTrue() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.error(new java.net.ConnectException("Connection refused")))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When
        orchestrator.run();

        // Then - Should retry
        verify(transactionalService, times(2))
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);
    }

    @Test
    @DisplayName("Should classify validation errors as non-retryable")
    void isRetryableError_ValidationError_ReturnsFalse() {
        // Given
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true));

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.error(new IllegalArgumentException("Invalid email")));

        doNothing().when(lockService).releaseBootstrapLock();

        // When/Then
        assertThatThrownBy(() -> orchestrator.run())
                .isInstanceOf(BootstrapInitializationException.class);

        // Should NOT retry
        verify(transactionalService, times(1))
                .createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);
    }

    /* =========================
       Concurrent Execution Tests
       ========================= */

    @Test
    @DisplayName("Should coordinate multiple instance startups")
    void run_MultipleInstances_OnlyOneExecutes() {
        // Given - Instance 1
        when(validationService.validateBootstrapConfig(appConfigProperties))
                .thenReturn(true);

        when(lockService.acquireBootstrapLock())
                .thenReturn(Mono.just(true)); // Instance 1 gets lock

        when(stateService.isBootstrapCompleted())
                .thenReturn(Mono.just(false));

        when(transactionalService.createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE))
                .thenReturn(Mono.just(BootstrapResult.created("user-123", true)));

        doNothing().when(lockService).releaseBootstrapLock();

        // When - Instance 1 runs
        orchestrator.run();

        // Then - Instance 1 executed
        verify(transactionalService).createSuperAdminTransactionally(TEST_EMAIL, TEST_PHONE);

        // Instance 2 would not get lock and would wait
        // (tested in run_LockNotAcquired_WaitsForCompletion)
    }
}
