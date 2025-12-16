package com.techStack.authSys.service.bootstrap;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.service.*;
import com.techStack.authSys.util.PasswordUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;

/**
 * Handles Super Admin account creation during bootstrap.
 * Ensures idempotent creation with proper error handling and rollback.
 *
 * IMPROVEMENTS:
 * - Added retry logic for transient failures
 * - Better error categorization
 * - Enhanced logging with structured context
 * - Fallback for notification failures
 * - Input validation
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SuperAdminCreationService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final BootstrapNotificationService notificationService;
    private final BootstrapStateService stateService;
    private final MetricsService metricsService;

    private static final String SYSTEM_CREATOR = "BOOTSTRAP_SYSTEM";
    private static final String SYSTEM_IP = "127.0.0.1";
    private static final String DEVICE_FINGERPRINT = "BOOTSTRAP_DEVICE";

    // Retry configuration
    private static final int MAX_RETRIES = 3;
    private static final Duration RETRY_DELAY = Duration.ofSeconds(2);

    /**
     * Creates Super Admin if it doesn't already exist.
     * Idempotent - safe to call multiple times.
     */
    public Mono<Void> createSuperAdminIfAbsent(String email, String phone) {
        // Validate inputs
        if (email == null || email.isBlank()) {
            log.error("❌ Email cannot be null or empty");
            return Mono.error(new IllegalArgumentException("Email is required"));
        }

        email = normalizeEmail(email);
        phone = normalizePhone(phone);

        String finalEmail = email;
        String finalPhone = phone;

        long startTime = System.currentTimeMillis();

        log.info("🚀 Bootstrap initiated for Super Admin: {}", maskEmail(finalEmail));

        return checkExistingAdmin(finalEmail)
                .flatMap(exists -> {
                    if (exists) {
                        log.info("⚠️ Super Admin already exists: {}", maskEmail(finalEmail));
                        return stateService.markBootstrapComplete()
                                .doOnSuccess(v -> log.info("✅ Bootstrap state verified"));
                    }

                    log.info("🔐 Creating new Super Admin account: {}", maskEmail(finalEmail));
                    return createSuperAdmin(finalEmail, finalPhone, startTime);
                })
                .doOnSuccess(v -> {
                    long duration = System.currentTimeMillis() - startTime;
                    log.info("🎉 Bootstrap process completed in {}ms", duration);
                })
                .doOnError(e -> {
                    long duration = System.currentTimeMillis() - startTime;
                    log.error("💥 Bootstrap process failed after {}ms: {}",
                            duration, e.getMessage());
                });
    }

    /**
     * Checks if Super Admin already exists.
     * Includes retry logic for transient database failures.
     */
    private Mono<Boolean> checkExistingAdmin(String email) {
        return firebaseServiceAuth.existsByEmail(email)
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRetryableError)
                        .doBeforeRetry(signal ->
                                log.warn("⚠️ Retrying existence check, attempt: {}",
                                        signal.totalRetries() + 1))
                        .onRetryExhaustedThrow((spec, signal) -> {
                            log.error("❌ Exhausted retries checking admin existence");
                            return new RuntimeException("Failed to check admin existence after " +
                                    MAX_RETRIES + " attempts", signal.failure());
                        }))
                .doOnSuccess(exists -> log.debug("📊 Admin existence check: {}", exists));
    }

    /**
     * Creates Super Admin with roles, permissions, and notifications.
     */
    private Mono<Void> createSuperAdmin(String email, String phone, long startTime) {
        String password = PasswordUtils.generateSecurePassword(16);
        User superAdmin = buildSuperAdminUser(email, phone, password);

        log.info("🔄 Starting Super Admin creation for {}", maskEmail(email));

        return firebaseServiceAuth.createSuperAdmin(
                        superAdmin,
                        password,
                        SYSTEM_IP,
                        DEVICE_FINGERPRINT
                )
                .doOnSuccess(user -> log.info("✅ Super Admin created with ID: {}", user.getId()))
                .flatMap(user -> finalizeBootstrap(user, password, startTime))
                .onErrorResume(e -> handleCreationError(email, e));
    }

    /**
     * Builds Super Admin user object with all required fields.
     */
    private User buildSuperAdminUser(String email, String phone, String password) {
        Instant now = Instant.now();

        User admin = new User();
        admin.setCreatedAt(now);
        admin.setUpdatedAt(now);
        admin.setCreatedBy(SYSTEM_CREATOR);
        admin.setEmail(email);
        admin.setEmailVerified(true);
        admin.setPhoneNumber(phone);
        admin.setPassword(password);
        admin.setStatus(User.Status.ACTIVE);
        admin.setEnabled(true);
        admin.setForcePasswordChange(true);
        admin.setAccountLocked(false);
        admin.setFirstName("Super");
        admin.setLastName("Admin");
        admin.setUsername("superadmin");
        admin.setDeviceFingerprint(DEVICE_FINGERPRINT);

        return admin;
    }

    /**
     * Finalizes bootstrap: marks complete, sends email, records metrics.
     * Enhanced with fallback handling for email failures.
     */
    private Mono<Void> finalizeBootstrap(User user, String password, long startTime) {
        long duration = System.currentTimeMillis() - startTime;

        log.info("📧 Finalizing bootstrap for {}", maskEmail(user.getEmail()));

        return Mono.when(
                        stateService.markBootstrapComplete()
                                .doOnSuccess(v -> log.debug("✓ Bootstrap marked complete"))
                                .doOnError(e -> log.error("✗ Failed to mark bootstrap complete: {}",
                                        e.getMessage())),

                        sendWelcomeEmailWithFallback(user.getEmail(), password)
                                .doOnSuccess(v -> log.debug("✓ Welcome email sent"))
                                .doOnError(e -> log.warn("✗ Email failed but continuing: {}",
                                        e.getMessage())),

                        recordBootstrapMetrics(user, duration)
                                .doOnSuccess(v -> log.debug("✓ Metrics recorded"))
                                .doOnError(e -> log.warn("✗ Metrics failed but continuing: {}",
                                        e.getMessage()))
                )
                .doOnSuccess(v -> log.info("✅ Super Admin bootstrap completed in {}ms for {}",
                        duration, maskEmail(user.getEmail())))
                .doOnError(e -> log.error("❌ Failed to finalize bootstrap: {}", e.getMessage()));
    }

    /**
     * Sends welcome email with fallback for failures.
     * Logs emergency password if email delivery fails completely.
     */
    private Mono<Void> sendWelcomeEmailWithFallback(String email, String password) {
        return notificationService.sendWelcomeEmail(email, password)
                .timeout(Duration.ofSeconds(30))
                .retryWhen(Retry.fixedDelay(2, Duration.ofSeconds(5))
                        .filter(this::isRetryableError)
                        .doBeforeRetry(signal ->
                                log.warn("⚠️ Retrying email send, attempt: {}",
                                        signal.totalRetries() + 1)))
                .onErrorResume(e -> {
                    log.error("❌ Email delivery failed after retries for {}: {}",
                            maskEmail(email), e.getMessage());
                    logEmergencyPassword(email, password, e);
                    // Don't fail bootstrap due to email failure
                    return Mono.empty();
                });
    }

    /**
     * Logs emergency password in formatted box for manual retrieval.
     */
    private void logEmergencyPassword(String email, String password, Throwable e) {
        log.error("╔════════════════════════════════════════════════════════════╗");
        log.error("║  🚨 EMERGENCY PASSWORD RECOVERY - EMAIL DELIVERY FAILED  ║");
        log.error("╠════════════════════════════════════════════════════════════╣");
        log.error("║  Email: {}║",
                String.format("%-50s", email));
        log.error("║  Password: {}║",
                String.format("%-47s", password));
        log.error("║  Failure: {}║",
                String.format("%-48s", e.getClass().getSimpleName()));
        log.error("╠════════════════════════════════════════════════════════════╣");
        log.error("║  CRITICAL SECURITY NOTICE:                                 ║");
        log.error("║  1. Copy this password IMMEDIATELY                         ║");
        log.error("║  2. Login and change password NOW                          ║");
        log.error("║  3. Clear application logs after retrieval                 ║");
        log.error("║  4. Fix email configuration before next bootstrap          ║");
        log.error("╚════════════════════════════════════════════════════════════╝");
    }

    /**
     * Records bootstrap metrics.
     */
    private Mono<Void> recordBootstrapMetrics(User user, long duration) {
        return Mono.fromRunnable(() -> {
            try {
                metricsService.incrementCounter("bootstrap.super_admin.created");
                metricsService.incrementCounter("user.registration.success");
                metricsService.recordTimer("bootstrap.creation.time", Duration.ofMillis(duration));

                log.info("📊 Bootstrap metrics recorded for {}", maskEmail(user.getEmail()));
            } catch (Exception e) {
                log.warn("⚠️ Failed to record metrics: {}", e.getMessage());
            }
        });
    }
    /**
     * Handles creation errors with intelligent rollback.
     */
    private Mono<Void> handleCreationError(String email, Throwable e) {
        log.error("🚨 Super Admin creation failed for {}: {}", maskEmail(email), e.getMessage(), e);

        // Record failure metric
        try {
            metricsService.incrementCounter("bootstrap.super_admin.failed");
        } catch (Exception metricError) {
            log.warn("Failed to record failure metric: {}", metricError.getMessage());
        }

        // Handle duplicate email scenario
        if (e instanceof FirebaseAuthException) {
            FirebaseAuthException fbEx = (FirebaseAuthException) e;
            String errorCode = fbEx.getAuthErrorCode() != null ?
                    fbEx.getAuthErrorCode().name() : "UNKNOWN";

            if ("EMAIL_EXISTS".equals(errorCode) || "EMAIL_ALREADY_EXISTS".equals(errorCode)) {
                log.warn("⚠️ Email already exists - marking bootstrap complete anyway");
                return stateService.markBootstrapComplete();
            }
        }

        // Attempt rollback for other errors
        log.warn("🔄 Attempting rollback for {}", maskEmail(email));
        return firebaseServiceAuth.rollbackFirebaseUserCreation(email)
                .timeout(Duration.ofSeconds(10))
                .doOnSuccess(v -> log.info("✅ Rollback completed for {}", maskEmail(email)))
                .doOnError(rollbackError ->
                        log.error("❌ Rollback failed: {}", rollbackError.getMessage()))
                .onErrorResume(rollbackError -> {
                    log.error("💥 Critical: Rollback failed. Manual cleanup may be required.");
                    return Mono.empty();
                })
                .then(Mono.error(e)); // Re-throw original error after rollback
    }

    /**
     * Determines if an error is retryable (transient network/database issues).
     */
    private boolean isRetryableError(Throwable e) {
        return e instanceof java.net.SocketException
                || e instanceof java.net.SocketTimeoutException
                || e instanceof java.io.IOException
                || e.getMessage() != null && (
                e.getMessage().contains("timeout")
                        || e.getMessage().contains("temporarily unavailable")
                        || e.getMessage().contains("connection reset"));
    }

    // ============================================================================
    // UTILITY METHODS
    // ============================================================================

    private String normalizeEmail(String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    private String normalizePhone(String phone) {
        if (phone == null || phone.isBlank()) return null;

        phone = phone.trim().replaceAll("\\s+", "");

        // Kenyan phone normalization
        if (phone.startsWith("0")) return "+254" + phone.substring(1);
        if (phone.startsWith("254")) return "+" + phone;
        if (!phone.startsWith("+")) return "+" + phone;

        return phone;
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] parts = email.split("@");
        int maskLength = Math.min(3, parts[0].length());
        return parts[0].substring(0, maskLength) + "***@" + parts[1];
    }
}