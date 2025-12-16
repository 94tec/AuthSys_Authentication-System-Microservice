package com.techStack.authSys.service.bootstrap;

import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.*;
import com.techStack.authSys.util.PasswordUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeoutException;

/**
 * Transactional Super Admin creation with automatic rollback.
 *
 * ENHANCEMENTS:
 * - Added retry logic for transient failures
 * - Input validation
 * - Better error categorization
 * - Enhanced rollback with timeout protection
 * - Improved observability and metrics
 * - Idempotency checks at each step
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TransactionalBootstrapService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RedisUserCacheService redisCacheService;
    private final BootstrapNotificationService notificationService;
    private final BootstrapStateService stateService;
    private final AuditLogService auditLogService;
    private final Firestore firestore;

    private static final String SYSTEM_CREATOR = "BOOTSTRAP_SYSTEM";
    private static final String SYSTEM_IP = "127.0.0.1";
    private static final String DEVICE_FINGERPRINT = "BOOTSTRAP_DEVICE";

    // Retry configuration
    private static final int MAX_RETRIES = 3;
    private static final Duration RETRY_DELAY = Duration.ofSeconds(2);
    private static final Duration OPERATION_TIMEOUT = Duration.ofSeconds(60);
    private static final Duration EMAIL_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration ROLLBACK_TIMEOUT = Duration.ofSeconds(15);

    /**
     * Creates Super Admin with full transactional guarantees.
     * If any step fails, all previous steps are rolled back.
     */
    public Mono<Void> createSuperAdminTransactionally(String email, String phone) {
        // Validate inputs
        if (email == null || email.isBlank()) {
            log.error("❌ Email cannot be null or empty");
            return Mono.error(new IllegalArgumentException("Email is required"));
        }

        email = normalizeEmail(email);
        phone = normalizePhone(phone);

        String finalEmail = email;
        String finalPhone = phone;

        TransactionContext ctx = new TransactionContext();
        ctx.startTime = System.currentTimeMillis();

        log.info("🚀 Bootstrap transaction initiated for: {}", maskEmail(finalEmail));

        return checkExistingAdmin(finalEmail)
                .flatMap(exists -> {
                    if (exists) {
                        log.info("⚠️ Super Admin already exists: {}", maskEmail(finalEmail));
                        return stateService.markBootstrapComplete()
                                .doOnSuccess(v -> logAlreadyExists(finalEmail, ctx));
                    }

                    log.info("🔐 Starting transactional Super Admin creation for: {}",
                            maskEmail(finalEmail));

                    return executeTransactionalCreation(finalEmail, finalPhone, ctx);
                })
                .doOnError(e -> performRollback(ctx, finalEmail, e))
                .onErrorResume(e -> handleFinalError(finalEmail, ctx, e));
    }

    /**
     * Checks if Super Admin already exists with retry logic.
     */
    private Mono<Boolean> checkExistingAdmin(String email) {
        return firebaseServiceAuth.existsByEmail(email)
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRetryableError)
                        .doBeforeRetry(signal ->
                                log.warn("⚠️ Retrying existence check, attempt: {}",
                                        signal.totalRetries() + 1)))
                .timeout(Duration.ofSeconds(10))
                .doOnSuccess(exists -> log.debug("📊 Admin existence check result: {}", exists))
                .onErrorResume(e -> {
                    log.error("❌ Failed to check admin existence: {}", e.getMessage());
                    return Mono.error(new RuntimeException("Cannot verify admin existence", e));
                });
    }

    /**
     * Executes the creation with rollback checkpoints.
     *
     * SIMPLIFIED FLOW (4 steps):
     * 1. Create Firebase user (Auth + Firestore + Roles + Permissions) - ATOMIC
     * 2. Cache email in Redis
     * 3. Mark bootstrap complete
     * 4. Send notification email
     */
    private Mono<Void> executeTransactionalCreation(
            String email,
            String phone,
            TransactionContext ctx) {

        String password = PasswordUtils.generateSecurePassword(16);
        User superAdmin = buildSuperAdminUser(email, phone, password);

        log.info("🔄 [TX-START] Beginning transactional creation for {}", maskEmail(email));

        return Mono.defer(() -> {
                    // STEP 1: Create Firebase user (ATOMIC: Auth + Firestore + Roles + Permissions)
                    return createFirebaseUserAtomically(superAdmin, password, ctx)
                            .doOnSuccess(u -> {
                                log.info("✓ Step 1/4: Firebase user created atomically");
                                ctx.completedSteps.add("FIREBASE_USER_CREATION");
                            })

                            // STEP 2: Cache email in Redis
                            .flatMap(user -> cacheEmailRegistration(user, ctx)
                                    .doOnSuccess(u -> {
                                        log.info("✓ Step 2/4: Email cached in Redis");
                                        ctx.completedSteps.add("REDIS_CACHE");
                                    }))

                            // STEP 3: Mark bootstrap complete
                            .flatMap(user -> markBootstrapCompleteTransactionally(ctx)
                                    .doOnSuccess(v -> {
                                        log.info("✓ Step 3/4: Bootstrap marked complete");
                                        ctx.completedSteps.add("BOOTSTRAP_FLAG");
                                    })
                                    .thenReturn(user))

                            // STEP 4: Send notification email
                            .flatMap(user -> {
                                log.info("▶ Step 4/4: Sending notification email to {}", maskEmail(email));
                                return sendNotificationWithFallback(email, password)
                                        .doOnSuccess(x -> {
                                            log.info("✓ Step 4/4: Notification completed");
                                            ctx.completedSteps.add("EMAIL_NOTIFICATION");
                                        });
                            })

                            // SUCCESS: Log completion
                            .doOnSuccess(v -> logSuccessfulBootstrap(email, ctx))

                            .then(); // Ensure void return
                })
                .timeout(OPERATION_TIMEOUT)
                .doOnError(e -> {
                    ctx.failureTime = System.currentTimeMillis();
                    log.error("❌ [TX-ERROR] Transaction failed at step {}: {}",
                            ctx.failurePoint, e.getMessage(), e);
                })
                .doFinally(signal -> {
                    ctx.endTime = System.currentTimeMillis();
                    log.info("🏁 [TX-END] Transaction completed with signal: {} in {}ms",
                            signal, ctx.getTotalDuration());
                });
    }

    /**
     * Creates Firebase Auth user with ATOMIC Firestore batch write.
     * Includes retry logic for transient failures.
     */
    private Mono<User> createFirebaseUserAtomically(User user, String password, TransactionContext ctx) {
        return firebaseServiceAuth.createSuperAdmin(
                        user,
                        password,
                        SYSTEM_IP,
                        DEVICE_FINGERPRINT
                )
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRetryableError)
                        .doBeforeRetry(signal ->
                                log.warn("⚠️ Retrying user creation, attempt: {}",
                                        signal.totalRetries() + 1)))
                .doOnSuccess(createdUser -> {
                    ctx.firebaseUserId = createdUser.getId();
                    ctx.firebaseUserEmail = createdUser.getEmail();
                    ctx.userSavedToFirestore = true;
                    ctx.rolesAssigned = true;
                    ctx.permissionsResolved = true;
                    log.info("✅ Step 1/4: Atomic creation completed - User ID: {}", ctx.firebaseUserId);
                })
                .doOnError(e -> {
                    log.error("❌ Step 1/4 FAILED: Atomic user creation: {}", e.getMessage());
                    ctx.failurePoint = "ATOMIC_USER_CREATION";
                });
    }

    /**
     * Caches email in Redis with rollback support.
     * Non-fatal - continues on failure.
     */
    private Mono<User> cacheEmailRegistration(User user, TransactionContext ctx) {
        return redisCacheService.cacheRegisteredEmail(user.getEmail())
                .timeout(Duration.ofSeconds(5))
                .doOnSuccess(v -> {
                    ctx.emailCachedInRedis = true;
                    log.debug("✅ Step 2/4: Email cached in Redis");
                })
                .doOnError(e -> {
                    log.warn("⚠️ Step 2/4 WARNING: Redis cache failed (non-fatal): {}",
                            e.getMessage());
                    ctx.failurePoint = "REDIS_EMAIL_CACHE";
                })
                .thenReturn(user)
                .onErrorReturn(user); // Redis failure is non-fatal
    }

    /**
     * Marks bootstrap as complete atomically with retry.
     */
    private Mono<Void> markBootstrapCompleteTransactionally(TransactionContext ctx) {
        return stateService.markBootstrapComplete()
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(this::isRetryableError)
                        .doBeforeRetry(signal ->
                                log.warn("⚠️ Retrying bootstrap complete, attempt: {}",
                                        signal.totalRetries() + 1)))
                .timeout(Duration.ofSeconds(10))
                .doOnSuccess(v -> {
                    ctx.bootstrapMarkedComplete = true;
                    log.debug("✅ Step 3/4: Bootstrap marked complete");
                })
                .doOnError(e -> {
                    log.error("❌ Step 3/4 FAILED: Mark complete: {}", e.getMessage());
                    ctx.failurePoint = "MARK_BOOTSTRAP_COMPLETE";
                });
    }

    /**
     * Sends welcome email with CRITICAL fallback logging.
     * SECURITY: Only logs password to console if email completely fails.
     */
    private Mono<Void> sendNotificationWithFallback(String email, String password) {
        log.info("🚀 [INIT] Starting email notification for {}", maskEmail(email));

        return notificationService.sendWelcomeEmail(email, password)
                .doOnSubscribe(s ->
                        log.debug("🔗 [SUBSCRIBED] Email operation subscribed for {}", maskEmail(email)))
                .timeout(EMAIL_TIMEOUT)
                .retryWhen(Retry.fixedDelay(2, Duration.ofSeconds(5))
                        .filter(this::isRetryableError)
                        .doBeforeRetry(signal ->
                                log.warn("⚠️ Retrying email send, attempt: {}",
                                        signal.totalRetries() + 1)))
                .doOnSuccess(v -> {
                    log.info("✅ [SUCCESS] Welcome email sent successfully to {}", maskEmail(email));
                })
                .doOnError(TimeoutException.class, e -> {
                    log.error("⏱️ [TIMEOUT] Email operation timed out after {}s for {}",
                            EMAIL_TIMEOUT.getSeconds(), maskEmail(email));
                    logEmergencyPassword(email, password, e);
                })
                .doOnError(e -> {
                    if (!(e instanceof TimeoutException)) {
                        log.error("❌ [ERROR] Email delivery failed for {}: {}",
                                maskEmail(email), e.getClass().getSimpleName());
                        log.error("❌ Error details: {}", e.getMessage(), e);
                        logEmergencyPassword(email, password, e);
                    }
                })
                .doOnCancel(() ->
                        log.warn("🚫 [CANCELLED] Email operation was cancelled for {}", maskEmail(email)))
                .doFinally(signalType ->
                        log.debug("🏁 [FINALLY] Email operation completed with signal: {} for {}",
                                signalType, maskEmail(email)))
                .onErrorResume(e -> {
                    log.warn("⚠️ [RESUME] Continuing bootstrap despite email failure - password logged above");
                    return Mono.empty();
                })
                .then();
    }

    /**
     * Logs emergency password in formatted box.
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

        logEmailFailure(email, e);
    }

    /**
     * Logs email failure to audit trail (WITHOUT password).
     */
    private void logEmailFailure(String email, Throwable error) {
        try {
            Map<String, Object> auditData = Map.of(
                    "timestamp", Instant.now().toString(),
                    "operation", "BOOTSTRAP_EMAIL_DELIVERY",
                    "status", "FAILED",
                    "email", maskEmail(email),
                    "error", error.getMessage(),
                    "errorType", error.getClass().getSimpleName(),
                    "severity", "CRITICAL",
                    "actionRequired", "Fix email configuration and resend credentials"
            );

            firestore.collection("audit_email_failures")
                    .document(UUID.randomUUID().toString())
                    .set(auditData)
                    .get();

        } catch (Exception e) {
            log.error("Failed to log email failure to audit: {}", e.getMessage());
        }
    }

    // ============================================================================
    // ROLLBACK SYSTEM
    // ============================================================================

    /**
     * Performs comprehensive rollback on failure.
     * Enhanced with timeout protection and better error handling.
     */
    private void performRollback(TransactionContext ctx, String email, Throwable error) {
        long duration = ctx.getFailureDuration();

        log.error("🔄 ROLLBACK INITIATED at step: {} after {}ms",
                ctx.failurePoint, duration);
        log.error("🔄 Error: {} - {}", error.getClass().getSimpleName(), error.getMessage());
        log.error("🔄 Completed steps before failure: {}", ctx.completedSteps);

        List<String> rollbackSteps = new ArrayList<>();
        List<String> rollbackFailures = new ArrayList<>();

        try {
            // Rollback in reverse order
            if (ctx.bootstrapMarkedComplete) {
                try {
                    rollbackBootstrapFlag();
                    rollbackSteps.add("bootstrap_flag");
                } catch (Exception e) {
                    log.error("Failed to rollback bootstrap flag: {}", e.getMessage());
                    rollbackFailures.add("bootstrap_flag: " + e.getMessage());
                }
            }

            if (ctx.emailCachedInRedis) {
                try {
                    rollbackRedisCache(email);
                    rollbackSteps.add("redis_cache");
                } catch (Exception e) {
                    log.error("Failed to rollback Redis cache: {}", e.getMessage());
                    rollbackFailures.add("redis_cache: " + e.getMessage());
                }
            }

            // UNIFIED: One rollback for atomic Firebase creation
            if (ctx.firebaseUserId != null) {
                try {
                    rollbackFirebaseUserAndData(email, ctx.firebaseUserId);
                    rollbackSteps.add("firebase_auth_and_firestore");
                } catch (Exception e) {
                    log.error("Failed to rollback Firebase data: {}", e.getMessage());
                    rollbackFailures.add("firebase_data: " + e.getMessage());
                }
            }

            if (rollbackFailures.isEmpty()) {
                log.info("✅ Rollback completed successfully. Cleaned: {}", rollbackSteps);
            } else {
                log.error("⚠️ Rollback completed with {} failures. Cleaned: {}, Failed: {}",
                        rollbackFailures.size(), rollbackSteps, rollbackFailures);
            }

        } catch (Exception rollbackError) {
            log.error("💥 CRITICAL: Rollback failed: {}", rollbackError.getMessage(), rollbackError);
            logCriticalRollbackFailure(ctx, error, rollbackError, rollbackSteps, rollbackFailures);
        }

        logTransactionFailure(ctx, email, error, rollbackSteps, rollbackFailures);
    }

    private void rollbackBootstrapFlag() {
        Mono.fromCallable(() -> {
                    firestore.collection("system_flags")
                            .document("bootstrap_admin")
                            .delete()
                            .get();
                    log.debug("🔄 Rolled back bootstrap flag");
                    return null;
                })
                .onErrorResume(e -> {
                    log.warn("⚠️ Failed to rollback bootstrap flag: {}", e.getMessage());
                    return Mono.empty();
                })
                .subscribeOn(Schedulers.boundedElastic());
    }
    private void rollbackRedisCache(String email) {
        redisCacheService.removeRegisteredEmail(email)
                .timeout(Duration.ofSeconds(5))
                .block();
        log.debug("🔄 Rolled back Redis email cache");
    }

    /**
     * UNIFIED ROLLBACK with timeout protection.
     */
    private void rollbackFirebaseUserAndData(String email, String userId) {
        // Delete Firebase Auth user with timeout
        firebaseServiceAuth.rollbackFirebaseUserCreation(email)
                .timeout(ROLLBACK_TIMEOUT)
                .doOnSuccess(v -> log.debug("🔄 Rolled back Firebase Auth user"))
                .doOnError(e -> log.error("Failed to rollback Firebase Auth: {}", e.getMessage()))
                .onErrorResume(e -> Mono.empty())
                .block();

        // Delete Firestore subcollections
        try {
            deleteFirestoreSubcollections(userId);
            log.debug("🔄 Rolled back Firestore subcollections");
        } catch (Exception e) {
            log.error("Failed to delete subcollections: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Deletes all subcollections created during atomic user creation.
     */
    private void deleteFirestoreSubcollections(String userId) {
        try {
            // Delete user_profiles subcollection
            deleteDocumentSafely("users/" + userId + "/user_profiles", "profile");

            // Delete user_permissions subcollection
            deleteDocumentSafely("users/" + userId + "/user_permissions", "active_permissions");

            // Delete password history entries
            firestore.collection("users")
                    .document(userId)
                    .collection("user_password_history")
                    .listDocuments()
                    .forEach(doc -> deleteDocumentSafely(doc));

            log.debug("🔄 Cleaned up Firestore subcollections for user: {}", userId);

        } catch (Exception e) {
            log.error("Failed to delete subcollections: {}", e.getMessage());
            throw new RuntimeException("Subcollection deletion failed", e);
        }
    }

    private void deleteDocumentSafely(String collectionPath, String documentId) {
        try {
            String[] parts = collectionPath.split("/");
            CollectionReference collection = parts.length == 2
                    ? firestore.collection(parts[0]).document(parts[1]).collection(parts[2])
                    : firestore.collection(collectionPath);

            collection.document(documentId).delete().get();
        } catch (Exception e) {
            log.warn("Failed to delete document {}/{}: {}", collectionPath, documentId, e.getMessage());
        }
    }

    private void deleteDocumentSafely(DocumentReference doc) {
        try {
            doc.delete().get();
        } catch (Exception e) {
            log.warn("Failed to delete document {}: {}", doc.getId(), e.getMessage());
        }
    }

    private void logCriticalRollbackFailure(
            TransactionContext ctx,
            Throwable originalError,
            Exception rollbackError,
            List<String> rollbackSteps,
            List<String> rollbackFailures) {

        Map<String, Object> criticalData = new HashMap<>();
        criticalData.put("timestamp", Instant.now().toString());
        criticalData.put("operation", "SUPER_ADMIN_BOOTSTRAP");
        criticalData.put("originalError", originalError.getMessage());
        criticalData.put("originalErrorType", originalError.getClass().getSimpleName());
        criticalData.put("rollbackError", rollbackError.getMessage());
        criticalData.put("failurePoint", ctx.failurePoint);
        criticalData.put("completedSteps", ctx.completedSteps);
        criticalData.put("rollbackStepsCompleted", rollbackSteps);
        criticalData.put("rollbackFailures", rollbackFailures);
        criticalData.put("context", ctx.toMap());
        criticalData.put("severity", "CRITICAL");
        criticalData.put("requiresManualCleanup", true);

        try {
            firestore.collection("audit_critical_failures")
                    .document(UUID.randomUUID().toString())
                    .set(criticalData)
                    .get();
        } catch (Exception e) {
            log.error("💥 FATAL: Cannot log critical failure: {}", e.getMessage());
        }
    }

    private void logTransactionFailure(
            TransactionContext ctx,
            String email,
            Throwable error,
            List<String> rollbackSteps,
            List<String> rollbackFailures) {

        try {
            Map<String, Object> context = new HashMap<>();
            context.put("email", maskEmail(email));
            context.put("duration", ctx.getFailureDuration());
            context.put("failurePoint", ctx.failurePoint);
            context.put("completedSteps", ctx.completedSteps);
            context.put("rollbackSteps", rollbackSteps);
            context.put("rollbackFailures", rollbackFailures);
            context.put("errorType", error.getClass().getSimpleName());

            auditLogService.logTransactionFailure(
                    "SUPER_ADMIN_BOOTSTRAP",
                    ctx.firebaseUserId,
                    error.getMessage(),
                    context
            );
        } catch (Exception e) {
            log.error("Failed to log transaction failure: {}", e.getMessage());
        }
    }

    // ============================================================================
    // ERROR HANDLING
    // ============================================================================

    /**
     * Final error handler after rollback.
     */
    private Mono<Void> handleFinalError(String email, TransactionContext ctx, Throwable e) {
        log.error("💥 Bootstrap failed after rollback for {}: {}", maskEmail(email), e.getMessage());

        // Handle specific error cases
        if (e instanceof FirebaseAuthException) {
            FirebaseAuthException fbEx = (FirebaseAuthException) e;
            String errorCode = fbEx.getAuthErrorCode() != null ?
                    fbEx.getAuthErrorCode().name() : "UNKNOWN";

            if ("EMAIL_EXISTS".equals(errorCode) || "EMAIL_ALREADY_EXISTS".equals(errorCode)) {
                log.warn("⚠️ Email conflict detected - attempting to mark bootstrap complete");
                return stateService.markBootstrapComplete()
                        .doOnSuccess(v -> log.info("✅ Bootstrap marked complete despite email conflict"))
                        .onErrorResume(ex -> Mono.empty());
            }
        }

        // Return empty to prevent application crash
        return Mono.empty();
    }

    /**
     * Determines if an error is retryable.
     */
    private boolean isRetryableError(Throwable e) {
        return e instanceof java.net.SocketException
                || e instanceof java.net.SocketTimeoutException
                || e instanceof java.io.IOException
                || e instanceof TimeoutException
                || (e.getMessage() != null && (
                e.getMessage().contains("timeout")
                        || e.getMessage().contains("temporarily unavailable")
                        || e.getMessage().contains("connection reset")
                        || e.getMessage().contains("UNAVAILABLE")));
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

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

    private void logSuccessfulBootstrap(String email, TransactionContext ctx) {
        long duration = ctx.getTotalDuration();
        log.info("✅ Super Admin bootstrap completed successfully in {}ms for {}",
                duration, maskEmail(email));
        log.info("📊 Completed steps: {}", ctx.completedSteps);
    }

    private void logAlreadyExists(String email, TransactionContext ctx) {
        long duration = ctx.getTotalDuration();
        log.info("✅ Bootstrap verification completed in {}ms - Admin already exists: {}",
                duration, maskEmail(email));
    }

    private String normalizeEmail(String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    private String normalizePhone(String phone) {
        if (phone == null || phone.isBlank()) return null;
        phone = phone.trim().replaceAll("\\s+", "");
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

    // ============================================================================
    // TRANSACTION CONTEXT
    // ============================================================================

    /**
     * Enhanced transaction context for better tracking and observability.
     */
    private static class TransactionContext {
        String firebaseUserId;
        String firebaseUserEmail;
        boolean rolesAssigned = false;
        boolean permissionsResolved = false;
        boolean userSavedToFirestore = false;
        boolean emailCachedInRedis = false;
        boolean bootstrapMarkedComplete = false;
        String failurePoint = "UNKNOWN";

        // Timing information
        long startTime;
        long failureTime;
        long endTime;

        // Step tracking
        List<String> completedSteps = new ArrayList<>();

        long getTotalDuration() {
            return (endTime > 0 ? endTime : System.currentTimeMillis()) - startTime;
        }

        long getFailureDuration() {
            return (failureTime > 0 ? failureTime : System.currentTimeMillis()) - startTime;
        }

        Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("firebaseUserId", firebaseUserId);
            map.put("firebaseUserEmail", maskEmailStatic(firebaseUserEmail));
            map.put("rolesAssigned", rolesAssigned);
            map.put("permissionsResolved", permissionsResolved);
            map.put("userSavedToFirestore", userSavedToFirestore);
            map.put("emailCachedInRedis", emailCachedInRedis);
            map.put("bootstrapMarkedComplete", bootstrapMarkedComplete);
            map.put("failurePoint", failurePoint);
            map.put("completedSteps", completedSteps);
            map.put("totalDuration", getTotalDuration());
            map.put("failureDuration", getFailureDuration());
            return map;
        }

        private static String maskEmailStatic(String email) {
            if (email == null || !email.contains("@")) return "***";
            String[] parts = email.split("@");
            int maskLength = Math.min(3, parts[0].length());
            return parts[0].substring(0, maskLength) + "***@" + parts[1];
        }
    }
}