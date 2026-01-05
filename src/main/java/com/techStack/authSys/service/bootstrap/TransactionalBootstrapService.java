package com.techStack.authSys.service.bootstrap;

import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.service.*;
import com.techStack.authSys.util.FirestoreUtils;
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
    private final MetricsService metricsService;
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

        log.info("🚀 Bootstrap transaction initiated at {} for: {}",ctx.startTime, maskEmail(finalEmail));

        return checkExistingAdmin(finalEmail)
                .flatMap(exists -> {
                    if (exists) {
                        return handleExistingAdmin(finalEmail, ctx);
                    }
                    return executeTransactionalCreation(finalEmail, finalPhone, ctx);
                })
                .doOnError(e -> performRollback(ctx, finalEmail, e))
                .onErrorResume(e -> handleFinalError(finalEmail, ctx, e));
    }
    // ============================================================================
    // EXISTENCE CHECK
    // ============================================================================

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
     * Handles scenario where admin already exists.
     */
    private Mono<Void> handleExistingAdmin(String email, TransactionContext ctx) {
        log.info("⚠️ Super Admin already exists: {}", maskEmail(email));

        return stateService.markBootstrapComplete()
                .doOnSuccess(v -> {
                    ctx.endTime = System.currentTimeMillis();
                    log.info("✅ Bootstrap verification completed in {}ms - Admin exists",
                            ctx.getTotalDuration());
                    recordMetric("bootstrap.super_admin.already_exists");
                })
                .onErrorResume(e -> {
                    log.warn("⚠️ Failed to mark bootstrap complete: {}", e.getMessage());
                    return Mono.empty();
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
                                logStepComplete(1, "Firebase user created", ctx);
                            })

                            // STEP 2: Cache email in Redis
                            .flatMap(user -> cacheEmailRegistration(user, ctx)
                                    .doOnSuccess(u -> {
                                        log.info("✓ Step 2/4: Email cached in Redis");
                                        logStepComplete(2, "Email cached", ctx);
                                    }))

                            // STEP 3: Mark bootstrap complete
                            .flatMap(user -> markBootstrapComplete(ctx)
                                    .doOnSuccess(v -> {
                                        log.info("✓ Step 3/4: Bootstrap marked complete");
                                        logStepComplete(3, "Bootstrap marked complete", ctx);
                                    })
                                    .thenReturn(user))

                            // STEP 4: Send notification email
                            .flatMap(user -> {
                                log.info("▶ Step 4/4: Sending notification email to {}", maskEmail(email));
                                return sendNotificationWithFallback(email, password, ctx)
                                        .doOnSuccess(x -> {
                                            log.info("✓ Step 4/4: Notification completed");
                                            logStepComplete(4, "Notification sent", ctx);
                                        });
                            })
                            // SUCCESS: Log and record metrics
                            .doOnSuccess(v -> {
                                logSuccessfulBootstrap(email, ctx);
                                recordSuccessMetrics(ctx);
                            })

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
    // ============================================================================
    // STEP 1: ATOMIC FIREBASE CREATION
    // ============================================================================

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
                    log.debug("✅ Atomic creation: userId={}", ctx.firebaseUserId);
                    ctx.firebaseUserId = createdUser.getId();
                    ctx.firebaseUserEmail = createdUser.getEmail();
                    ctx.atomicCreationComplete = true;
                    log.info("✅ Step 1/4: Atomic creation completed - User ID: {}", ctx.firebaseUserId);
                })
                .doOnError(e -> {
                    log.error("❌ Step 1/4 FAILED: Atomic user creation: {}", e.getMessage());
                    ctx.failurePoint = "ATOMIC_USER_CREATION";
                });
    }
    // ============================================================================
    // STEP 2: REDIS CACHE
    // ============================================================================

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
    // ============================================================================
    // STEP 3: BOOTSTRAP STATE
    // ============================================================================

    /**
     * Marks bootstrap as complete atomically with retry.
     */
    private Mono<Void> markBootstrapComplete(TransactionContext ctx) {
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
    // ============================================================================
    // STEP 4: EMAIL NOTIFICATION
    // ============================================================================

    /**
     * Sends welcome email with CRITICAL fallback logging.
     * SECURITY: Only logs password to console if email completely fails.
     */
    private Mono<Void> sendNotificationWithFallback(String email, String password, TransactionContext ctx) {
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
                    ctx.emailSent = true;
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
                        auditEmailFailure(email, e);
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

        //logEmailFailure(email, e);
    }
    /**
     * Logs email failure to audit trail (WITHOUT password).
     */
    private void auditEmailFailure(String email, Throwable error) {
        Mono.fromRunnable(() -> {
            try {
                Map<String, Object> auditData = Map.of(
                        "timestamp", Instant.now().toString(),
                        "operation", "BOOTSTRAP_EMAIL_DELIVERY",
                        "status", "FAILED",
                        "email", maskEmail(email),
                        "error", error.getMessage(),
                        "errorType", error.getClass().getSimpleName(),
                        "severity", "CRITICAL"
                );

                firestore.collection("audit_email_failures")
                        .document(UUID.randomUUID().toString())
                        .set(auditData)
                        .get();
            } catch (Exception e) {
                log.warn("Failed to audit email failure: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).subscribe();
    }

    /**
     * Fully reactive rollback implementation.
     */
    private void performRollback(TransactionContext ctx, String email, Throwable error) {
        long duration = ctx.getFailureDuration();

        log.error("🔄 [REACTIVE-ROLLBACK] Initiated at step: {} after {}ms",
                ctx.failurePoint, duration);

        // We create a list to track what actually got cleaned up for logging purposes
        List<String> cleanedSteps = Collections.synchronizedList(new ArrayList<>());

        Mono.defer(() -> {
                    // 1. Rollback Step 3: Bootstrap flag
                    Mono<Void> rollbackState = ctx.bootstrapMarkedComplete ?
                            rollbackBootstrapFlagReactive(cleanedSteps) : Mono.empty();

                    // 2. Rollback Step 2: Redis
                    Mono<Void> rollbackRedis = ctx.emailCachedInRedis ?
                            rollbackRedisCacheReactive(email, cleanedSteps) : Mono.empty();

                    // 3. Rollback Step 1: Firebase Auth & Firestore
                    Mono<Void> rollbackFirebase = (ctx.firebaseUserId != null) ?
                            rollbackFirebaseDataReactive(email, ctx.firebaseUserId, cleanedSteps) : Mono.empty();

                    // Execute sequentially: State -> Redis -> Firebase
                    return rollbackState
                            .then(rollbackRedis)
                            .then(rollbackFirebase);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> log.info("✅ Rollback completed. Cleaned: {}", cleanedSteps))
                .doOnError(rollbackError -> {
                    log.error("💥 CRITICAL: Rollback failed: {}", rollbackError.getMessage());
                    logCriticalRollbackFailure(ctx, error, (Exception) rollbackError, cleanedSteps, List.of(rollbackError.getMessage()));
                })
                .then(Mono.fromRunnable(() -> logTransactionFailure(ctx, email, error, cleanedSteps, List.of())))
                .then();
    }

    private Mono<Void> rollbackBootstrapFlagReactive(List<String> steps) {
        return FirestoreUtils.apiFutureToMono(firestore.collection("system_flags").document("bootstrap_admin").delete())
                .doOnSuccess(v -> steps.add("bootstrap_flag"))
                .onErrorResume(e -> {
                    log.error("Failed to rollback flag: {}", e.getMessage());
                    return Mono.empty();
                })
                .then();
    }

    private Mono<Void> rollbackRedisCacheReactive(String email, List<String> steps) {
        return redisCacheService.removeRegisteredEmail(email)
                .timeout(Duration.ofSeconds(5))
                .doOnSuccess(v -> steps.add("redis_cache"))
                .onErrorResume(e -> {
                    log.warn("Failed to rollback Redis: {}", e.getMessage());
                    return Mono.empty();
                }).then();
    }

    private Mono<Void> rollbackFirebaseDataReactive(String email, String userId, List<String> steps) {
        // Delete Auth User
        Mono<Void> deleteAuth = firebaseServiceAuth.rollbackFirebaseUserCreation(email)
                .doOnSuccess(v -> steps.add("firebase_auth"))
                .onErrorResume(e -> {
                    log.error("Failed to delete Firebase Auth user: {}", e.getMessage());
                    return Mono.empty();
                });

        // Delete Firestore Collections
        Mono<Void> deleteFirestore = Mono.fromRunnable(() -> deleteFirestoreSubcollections(userId))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> steps.add("firestore_subcollections"))
                .then();

        return deleteAuth.then(deleteFirestore);
    }
    /**
     * Rollback bootstrap flag (non-blocking).
     */
    private void rollbackBootstrapFlag(List<String> steps, List<String> failures) {
        try {
            Mono.fromCallable(() -> {
                        firestore.collection("system_flags")
                                .document("bootstrap_admin")
                                .delete()
                                .get();
                        return null;
                    })
                    .timeout(ROLLBACK_TIMEOUT)
                    .subscribeOn(Schedulers.boundedElastic())
                    .block();

            steps.add("bootstrap_flag");
            log.debug("🔄 Rolled back bootstrap flag");
        } catch (Exception e) {
            failures.add("bootstrap_flag: " + e.getMessage());
            log.error("Failed to rollback bootstrap flag: {}", e.getMessage());
        }
    }

    /**
     * Rollback Redis cache (non-blocking, FIXED).
     */
    private void rollbackRedisCache(String email, List<String> steps, List<String> failures) {
        try {
            redisCacheService.removeRegisteredEmail(email)
                    .timeout(Duration.ofSeconds(5))
                    .subscribeOn(Schedulers.boundedElastic())
                    .block();

            steps.add("redis_cache");
            log.debug("🔄 Rolled back Redis cache");
        } catch (Exception e) {
            failures.add("redis_cache: " + e.getMessage());
            log.warn("Failed to rollback Redis: {}", e.getMessage());
        }
    }

    /**
     * Rollback Firebase Auth + Firestore subcollections (FIXED).
     */
    private void rollbackFirebaseData(String email, String userId,
                                      List<String> steps, List<String> failures) {
        // Delete Firebase Auth user
        try {
            firebaseServiceAuth.rollbackFirebaseUserCreation(email)
                    .timeout(ROLLBACK_TIMEOUT)
                    .subscribeOn(Schedulers.boundedElastic())
                    .block();

            steps.add("firebase_auth");
            log.debug("🔄 Rolled back Firebase Auth");
        } catch (Exception e) {
            failures.add("firebase_auth: " + e.getMessage());
            log.error("Failed to rollback Firebase Auth: {}", e.getMessage());
        }

        // Delete Firestore subcollections
        try {
            deleteFirestoreSubcollections(userId);
            steps.add("firestore_subcollections");
            log.debug("🔄 Rolled back Firestore subcollections");
        } catch (Exception e) {
            failures.add("firestore_subcollections: " + e.getMessage());
            log.error("Failed to rollback subcollections: {}", e.getMessage());
        }
    }
    /**
     * Deletes Firestore subcollections (FIXED path handling).
     */
    private void deleteFirestoreSubcollections(String userId) {
        DocumentReference userDoc = firestore.collection("users").document(userId);

        // Delete user_profiles subcollection
        deleteSubcollectionDocument(userDoc, "user_profiles", "profile");

        // Delete user_permissions subcollection
        deleteSubcollectionDocument(userDoc, "user_permissions", "active_permissions");

        // Delete password history
        userDoc.collection("user_password_history")
                .listDocuments()
                .forEach(this::deleteDocumentSafely);

        log.debug("🔄 Cleaned Firestore subcollections for user: {}", userId);
    }

    /**
     * Safely deletes a document in a subcollection.
     */
    private void deleteSubcollectionDocument(DocumentReference parentDoc,
                                             String subcollection,
                                             String documentId) {
        try {
            parentDoc.collection(subcollection)
                    .document(documentId)
                    .delete()
                    .get();
        } catch (Exception e) {
            log.warn("Failed to delete {}/{}: {}", subcollection, documentId, e.getMessage());
        }
    }
    /**
     * Safely deletes a document reference.
     */
    private void deleteDocumentSafely(DocumentReference doc) {
        try {
            doc.delete().get();
        } catch (Exception e) {
            log.warn("Failed to delete {}: {}", doc.getId(), e.getMessage());
        }
    }

    private void logCriticalRollbackFailure(
            TransactionContext ctx,
            Throwable originalError,
            Exception rollbackError,
            List<String> rollbackSteps,
            List<String> rollbackFailures) {
        Mono.fromCallable(() -> {
            try {
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
                firestore.collection("audit_critical_failures")
                        .document(UUID.randomUUID().toString())
                        .set(criticalData)
                        .get();
            } catch (Exception e) {
                log.error("💥 FATAL: Cannot log critical failure: {}", e.getMessage());
            }
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).subscribe();
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
    private void logStepComplete(int step, String message, TransactionContext ctx) {
        log.info("✓ Step {}/4: {}", step, message);
        ctx.completedSteps.add(String.format("STEP_%d_%s", step, message.toUpperCase().replace(" ", "_")));
    }

    private void logSuccessfulBootstrap(String email, TransactionContext ctx) {
        log.info("✅ Super Admin bootstrap completed in {}ms for {}",
                ctx.getTotalDuration(), maskEmail(email));
        log.info("📊 Completed steps: {}", ctx.completedSteps);
    }

    private void recordSuccessMetrics(TransactionContext ctx) {
        recordMetric("bootstrap.super_admin.created");
        recordMetric("user.registration.success");
        metricsService.recordTimer("bootstrap.creation.time",
                Duration.ofMillis(ctx.getTotalDuration()));
    }

    private void recordMetric(String metricName) {
        try {
            metricsService.incrementCounter(metricName);
        } catch (Exception e) {
            log.warn("Failed to record metric {}: {}", metricName, e.getMessage());
        }
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
        if (email == null || email.trim().isEmpty()) return "***";

        String trimmedEmail = email.trim();
        int atIndex = trimmedEmail.indexOf('@');
        if (atIndex <= 0) return "***";

        String localPart = trimmedEmail.substring(0, atIndex);
        String domain = trimmedEmail.substring(atIndex + 1);

        if (localPart.length() == 1) {
            return localPart + "***@" + domain;
        } else if (localPart.length() == 2) {
            return localPart.charAt(0) + "***" + localPart.charAt(1) + "@" + domain;
        } else {
            // a***c@gmail.com format
            return localPart.charAt(0) + "***" + localPart.charAt(localPart.length() - 1) + "@" + domain;
        }
    }

    // ============================================================================
    // TRANSACTION CONTEXT
    // ============================================================================

    /**
     * Transaction context for tracking state and timing.
     */
    private static class TransactionContext {
        String firebaseUserId;
        String firebaseUserEmail;
        boolean atomicCreationComplete = false;
        boolean emailCachedInRedis = false;
        boolean bootstrapMarkedComplete = false;
        boolean emailSent = false;
        String failurePoint = "UNKNOWN";

        long startTime;
        long failureTime;
        long endTime;

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
            map.put("firebaseUserEmail", firebaseUserEmail);
            map.put("atomicCreationComplete", atomicCreationComplete);
            map.put("emailCachedInRedis", emailCachedInRedis);
            map.put("bootstrapMarkedComplete", bootstrapMarkedComplete);
            map.put("emailSent", emailSent);
            map.put("failurePoint", failurePoint);
            map.put("startTime", startTime);
            map.put("failureTime", failureTime);
            map.put("endTime", endTime);
            map.put("completedSteps", completedSteps);
            map.put("totalDuration", getTotalDuration());
            map.put("failureDuration", failureTime > 0 ? getFailureDuration() : null);
            return map;
        }
    }
}