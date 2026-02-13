package com.techStack.authSys.service.bootstrap;

import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.dto.response.BootstrapResult;
import com.techStack.authSys.exception.bootstrap.BootstrapInitializationException;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtils;
import com.techStack.authSys.util.validation.HelperUtils;
import com.techStack.authSys.util.password.PasswordUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeoutException;

import static com.techStack.authSys.constants.SecurityConstants.DEVICE_FINGERPRINT;
import static com.techStack.authSys.constants.SecurityConstants.SYSTEM_IP;

/**
 * Transactional Super Admin creation with automatic rollback.
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
    private final FirestoreUserRepository firestoreUserRepository;
    private final Clock clock;

    private static final int MAX_RETRIES = 3;
    private static final Duration RETRY_DELAY = Duration.ofSeconds(2);
    private static final Duration OPERATION_TIMEOUT = Duration.ofSeconds(60);
    private static final Duration EMAIL_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration ROLLBACK_TIMEOUT = Duration.ofSeconds(15);

    /* =========================
       Public Entry Point
       ========================= */

    public Mono<BootstrapResult> createSuperAdminTransactionally(String email, String phone) {
        if (email == null || email.isBlank()) {
            return Mono.error(new IllegalArgumentException("Email is required"));
        }

        email = HelperUtils.normalizeEmail(email);
        phone = HelperUtils.normalizePhone(phone);

        String finalEmail = email;
        String finalPhone = phone;

        TransactionContext ctx = new TransactionContext();
        ctx.startTime = System.currentTimeMillis();

        log.info("🚀 Bootstrap transaction initiated for: {}", HelperUtils.maskEmail(finalEmail));

        return checkExistingAdmin(finalEmail)
                .flatMap(exists -> exists
                        ? handleExistingAdmin(finalEmail, ctx)
                        : executeTransactionalCreation(finalEmail, finalPhone, ctx))
                .doOnError(e -> performRollback(ctx, finalEmail, e))
                .onErrorResume(e -> handleFinalError(finalEmail, ctx, e));
    }

    /* =========================
       Step 0 — Existence Check
       ========================= */

    private Mono<Boolean> checkExistingAdmin(String email) {
        return firebaseServiceAuth.existsByEmail(email)
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(HelperUtils::isRetryableError)
                        .doBeforeRetry(s -> log.warn("⚠️ Retrying existence check (attempt {})",
                                s.totalRetries() + 1)))
                .timeout(Duration.ofSeconds(10))
                .doOnSuccess(exists -> metricsService.incrementCounter("bootstrap.admin.check.success"))
                .doOnError(e -> metricsService.incrementCounter("bootstrap.admin.check.error"))
                .onErrorResume(e -> {
                    log.error("❌ Cannot verify admin existence: {}", e.getMessage());
                    return Mono.error(new RuntimeException("Cannot verify admin existence", e));
                });
    }

    /* =========================
       Handle Existing Admin
       ========================= */

    private Mono<BootstrapResult> handleExistingAdmin(String email, TransactionContext ctx) {
        log.info("⚠️ Super Admin already exists: {}", HelperUtils.maskEmail(email));

        return stateService.markBootstrapComplete()
                .then(firebaseServiceAuth.findByEmail(email))
                .map(existingUser -> {
                    ctx.endTime = System.currentTimeMillis();
                    log.info("✅ Bootstrap verified in {}ms — Admin exists", ctx.getTotalDuration());
                    recordMetric("bootstrap.super_admin.already_exists");
                    return BootstrapResult.alreadyExists(existingUser.getId());
                })
                .onErrorResume(e -> {
                    log.warn("⚠️ Could not mark bootstrap complete: {}", e.getMessage());
                    return Mono.just(BootstrapResult.alreadyExists(null));
                });
    }

    /* =========================
       Transactional Creation
       ========================= */

    private Mono<BootstrapResult> executeTransactionalCreation(
            String email, String phone, TransactionContext ctx) {

        String password = PasswordUtils.generateSecurePassword(16);
        User superAdmin = HelperUtils.buildSuperAdminUser(email, phone, password);

        log.info("🔄 [TX-START] Beginning transactional creation for {}",
                HelperUtils.maskEmail(email));

        return Mono.defer(() ->

                        // ✅ STEP 1: Firebase Auth + Firestore (atomic, real UID assigned here)
                        createFirebaseUserAtomically(superAdmin, password, ctx)
                                .doOnSuccess(u -> logStepComplete(1, "Firebase Auth + Firestore saved", ctx))

                                // STEP 2: Cache email in Redis (non-fatal)
                                .flatMap(user -> cacheEmailRegistration(user, ctx)
                                        .doOnSuccess(u -> logStepComplete(2, "Email cached in Redis", ctx)))

                                // STEP 3: Mark bootstrap complete
                                .flatMap(user -> markBootstrapComplete(ctx)
                                        .doOnSuccess(v -> logStepComplete(3, "Bootstrap marked complete", ctx))
                                        .thenReturn(user))

                                // STEP 4: Send notification email (non-fatal)
                                .flatMap(user -> sendNotificationWithFallback(email, password, ctx)
                                        .then(Mono.just(user))
                                        .doOnSuccess(u -> logStepComplete(4, "Notification sent", ctx)))

                                // Build result
                                .map(user -> {
                                    logSuccessfulBootstrap(email, ctx);
                                    recordSuccessMetrics(ctx);
                                    return BootstrapResult.created(user.getId(), ctx.emailSent);
                                })
                )
                .timeout(OPERATION_TIMEOUT)
                .doOnError(e -> {
                    ctx.failureTime = System.currentTimeMillis();
                    log.error("❌ [TX-ERROR] Transaction failed at '{}': {}",
                            ctx.failurePoint, e.getMessage(), e);
                })
                .doFinally(signal -> {
                    ctx.endTime = System.currentTimeMillis();
                    log.info("🏁 [TX-END] Signal: {} in {}ms", signal, ctx.getTotalDuration());
                });
    }

    /* =========================
       Step 1 — Firebase Auth + Firestore
       ========================= */

    private Mono<User> createFirebaseUserAtomically(
            User user, String password, TransactionContext ctx) {

        return firebaseServiceAuth.createSuperAdmin(user, password, SYSTEM_IP, DEVICE_FINGERPRINT)
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(HelperUtils::isRetryableError)
                        .doBeforeRetry(s -> log.warn("⚠️ Retrying user creation (attempt {})",
                                s.totalRetries() + 1)))
                .doOnSuccess(createdUser -> {
                    ctx.firebaseUserId = createdUser.getId();
                    ctx.firebaseUserEmail = createdUser.getEmail();
                    ctx.atomicCreationComplete = true;
                    log.info("✅ Step 1: User created — UID: {}", ctx.firebaseUserId);
                })
                .doOnError(e -> {
                    log.error("❌ Step 1 FAILED: {}", e.getMessage());
                    ctx.failurePoint = "ATOMIC_USER_CREATION";
                });
    }

    /* =========================
       Step 2 — Redis Cache
       ========================= */

    private Mono<User> cacheEmailRegistration(User user, TransactionContext ctx) {
        return redisCacheService.cacheRegisteredEmail(user.getEmail())
                .timeout(Duration.ofSeconds(5))
                .doOnSuccess(v -> ctx.emailCachedInRedis = true)
                .doOnError(e -> {
                    log.warn("⚠️ Step 2 WARNING: Redis cache failed (non-fatal): {}",
                            e.getMessage());
                    ctx.failurePoint = "REDIS_EMAIL_CACHE";
                })
                .thenReturn(user)
                .onErrorReturn(user); // Redis failure is non-fatal
    }

    /* =========================
       Step 3 — Bootstrap State
       ========================= */

    private Mono<Void> markBootstrapComplete(TransactionContext ctx) {
        return stateService.markBootstrapComplete()
                .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                        .filter(HelperUtils::isRetryableError)
                        .doBeforeRetry(s -> log.warn("⚠️ Retrying mark complete (attempt {})",
                                s.totalRetries() + 1)))
                .timeout(Duration.ofSeconds(10))
                .doOnSuccess(v -> ctx.bootstrapMarkedComplete = true)
                .doOnError(e -> {
                    log.error("❌ Step 3 FAILED: {}", e.getMessage());
                    ctx.failurePoint = "MARK_BOOTSTRAP_COMPLETE";
                });
    }

    /* =========================
       Step 4 — Email Notification
       ========================= */

    private Mono<Void> sendNotificationWithFallback(
            String email, String password, TransactionContext ctx) {

        return notificationService.sendWelcomeEmail(email, password)
                .timeout(EMAIL_TIMEOUT)
                .retryWhen(Retry.fixedDelay(2, Duration.ofSeconds(5))
                        .filter(HelperUtils::isRetryableError)
                        .doBeforeRetry(s -> log.warn("⚠️ Retrying email (attempt {})",
                                s.totalRetries() + 1)))
                .doOnSuccess(v -> {
                    ctx.emailSent = true;
                    log.info("✅ Welcome email sent to {}", HelperUtils.maskEmail(email));
                })
                .doOnError(TimeoutException.class, e ->
                        logEmergencyPassword(email, password, e))
                .doOnError(e -> {
                    if (!(e instanceof TimeoutException)) {
                        logEmergencyPassword(email, password, e);
                        auditEmailFailure(email, e);
                    }
                })
                .onErrorResume(e -> {
                    log.warn("⚠️ Continuing bootstrap despite email failure — password logged above");
                    return Mono.empty();
                })
                .then();
    }

    private void logEmergencyPassword(String email, String password, Throwable e) {
        log.error("╔════════════════════════════════════════════════════════════╗");
        log.error("║  🚨 EMERGENCY PASSWORD RECOVERY - EMAIL DELIVERY FAILED  ║");
        log.error("╠════════════════════════════════════════════════════════════╣");
        log.error("║  Email:   {}║", String.format("%-48s", email));
        log.error("║  Password:{}║", String.format("%-48s", password));
        log.error("║  Failure: {}║", String.format("%-48s", e.getClass().getSimpleName()));
        log.error("╠════════════════════════════════════════════════════════════╣");
        log.error("║  1. Copy this password IMMEDIATELY                         ║");
        log.error("║  2. Login and change password NOW                          ║");
        log.error("║  3. Clear application logs after retrieval                 ║");
        log.error("╚════════════════════════════════════════════════════════════╝");
    }

    private void auditEmailFailure(String email, Throwable error) {
        Mono.fromRunnable(() -> {
            try {
                Map<String, Object> data = Map.of(
                        "timestamp", Instant.now().toString(),
                        "operation", "BOOTSTRAP_EMAIL_DELIVERY",
                        "status", "FAILED",
                        "email", HelperUtils.maskEmail(email),
                        "error", error.getMessage(),
                        "errorType", error.getClass().getSimpleName(),
                        "severity", "CRITICAL"
                );
                firestore.collection("audit_email_failures")
                        .document(UUID.randomUUID().toString())
                        .set(data).get();
            } catch (Exception e) {
                log.warn("Failed to audit email failure: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).subscribe();
    }

    /* =========================
       Rollback
       ========================= */

    private void performRollback(TransactionContext ctx, String email, Throwable error) {
        log.error("🔄 [ROLLBACK] Initiated at step: '{}' after {}ms",
                ctx.failurePoint, ctx.getFailureDuration());

        List<String> cleaned = Collections.synchronizedList(new ArrayList<>());

        Mono.defer(() -> {
                    Mono<Void> rollbackState = ctx.bootstrapMarkedComplete
                            ? rollbackBootstrapFlag(cleaned) : Mono.empty();

                    Mono<Void> rollbackRedis = ctx.emailCachedInRedis
                            ? rollbackRedisCache(email, cleaned) : Mono.empty();

                    Mono<Void> rollbackFirebase = ctx.firebaseUserId != null
                            ? rollbackFirebaseData(email, ctx.firebaseUserId, cleaned) : Mono.empty();

                    return rollbackState.then(rollbackRedis).then(rollbackFirebase);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> log.info("✅ Rollback completed. Cleaned: {}", cleaned))
                .doOnError(re -> log.error("💥 CRITICAL: Rollback failed: {}", re.getMessage()))
                .then(Mono.fromRunnable(() -> logTransactionFailure(ctx, email, error, cleaned)))
                .subscribe();
    }

    private Mono<Void> rollbackBootstrapFlag(List<String> steps) {
        return FirestoreUtils.apiFutureToMono(
                        firestore.collection("system_flags")
                                .document("bootstrap_admin").delete())
                .doOnSuccess(v -> steps.add("bootstrap_flag"))
                .onErrorResume(e -> {
                    log.error("Failed to rollback bootstrap flag: {}", e.getMessage());
                    return Mono.empty();
                }).then();
    }

    private Mono<Void> rollbackRedisCache(String email, List<String> steps) {
        return redisCacheService.removeRegisteredEmail(email)
                .timeout(Duration.ofSeconds(5))
                .doOnSuccess(v -> steps.add("redis_cache"))
                .onErrorResume(e -> {
                    log.warn("Failed to rollback Redis: {}", e.getMessage());
                    return Mono.empty();
                }).then();
    }

    private Mono<Void> rollbackFirebaseData(
            String email, String userId, List<String> steps) {

        Mono<Void> deleteAuth = Mono.fromRunnable(() -> {
            try {
                FirebaseAuth.getInstance().deleteUser(userId);
                steps.add("firebase_auth");
                log.debug("🔄 Rolled back Firebase Auth user: {}", userId);
            } catch (FirebaseAuthException e) {
                log.error("Failed to delete Firebase Auth user: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();

        Mono<Void> deleteFirestore = firestoreUserRepository.delete(userId)
                .doOnSuccess(v -> steps.add("firestore_user"))
                .onErrorResume(e -> {
                    log.error("Failed to delete Firestore user: {}", e.getMessage());
                    return Mono.empty();
                });

        return deleteAuth.then(deleteFirestore);
    }

    /* =========================
       Error Handling
       ========================= */

    private Mono<BootstrapResult> handleFinalError(
            String email, TransactionContext ctx, Throwable e) {

        log.error("💥 Bootstrap failed after rollback for {}: {}",
                HelperUtils.maskEmail(email), e.getMessage());

        String failurePoint = ctx.failurePoint != null ? ctx.failurePoint : "UNKNOWN";

        if (e instanceof com.google.firebase.auth.FirebaseAuthException) {
            com.google.firebase.auth.FirebaseAuthException fbEx =
                    (com.google.firebase.auth.FirebaseAuthException) e;
            String code = fbEx.getAuthErrorCode() != null
                    ? fbEx.getAuthErrorCode().name() : "UNKNOWN";

            if ("EMAIL_EXISTS".equals(code) || "EMAIL_ALREADY_EXISTS".equals(code)) {
                log.warn("⚠️ Email conflict — marking bootstrap complete");
                return stateService.markBootstrapComplete()
                        .then(firebaseServiceAuth.findByEmail(email))
                        .map(user -> BootstrapResult.alreadyExists(user.getId()))
                        .onErrorResume(ex -> Mono.error(
                                new BootstrapInitializationException(
                                        "Email exists but cannot mark bootstrap complete",
                                        "EMAIL_CONFLICT_RECOVERY", ex, false)));
            }
        }

        return Mono.error(new BootstrapInitializationException(
                "Bootstrap transaction failed: " + e.getMessage(),
                failurePoint, e, HelperUtils.isRetryableError(e)));
    }

    /* =========================
       Helpers
       ========================= */

    private void logStepComplete(int step, String message, TransactionContext ctx) {
        ctx.completedSteps.add(String.format("STEP_%d_%s",
                step, message.toUpperCase().replace(" ", "_")));
        log.info("✓ Step {}/4: {}", step, message);
    }

    private void logSuccessfulBootstrap(String email, TransactionContext ctx) {
        log.info("✅ Bootstrap completed in {}ms for {}",
                ctx.getTotalDuration(), HelperUtils.maskEmail(email));
        log.info("📊 Completed steps: {}", ctx.completedSteps);
    }

    private void recordSuccessMetrics(TransactionContext ctx) {
        recordMetric("bootstrap.super_admin.created");
        recordMetric("user.registration.success");
        metricsService.recordTimer("bootstrap.creation.time",
                Duration.ofMillis(ctx.getTotalDuration()));
    }

    private void recordMetric(String name) {
        try {
            metricsService.incrementCounter(name);
        } catch (Exception e) {
            log.warn("Failed to record metric {}: {}", name, e.getMessage());
        }
    }

    private void logTransactionFailure(
            TransactionContext ctx, String email, Throwable error, List<String> cleaned) {
        try {
            Map<String, Object> context = new HashMap<>();
            context.put("email", HelperUtils.maskEmail(email));
            context.put("duration", ctx.getFailureDuration());
            context.put("failurePoint", ctx.failurePoint);
            context.put("completedSteps", ctx.completedSteps);
            context.put("cleanedSteps", cleaned);
            context.put("errorType", error.getClass().getSimpleName());

            auditLogService.logTransactionFailure(
                    "SUPER_ADMIN_BOOTSTRAP",
                    ctx.firebaseUserId,
                    error.getMessage(),
                    context);
        } catch (Exception e) {
            log.error("Failed to log transaction failure: {}", e.getMessage());
        }
    }

    /* =========================
       Transaction Context
       ========================= */

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
    }
}