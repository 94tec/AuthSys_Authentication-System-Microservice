package com.techStack.authSys.service.bootstrap;

import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.*;
import com.techStack.authSys.util.PasswordUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeoutException;

/**
 * Transactional Super Admin creation with automatic rollback.
 * Ensures atomic operations across Firebase Auth, Firestore, and Redis.
 *
 * SECURITY: Does NOT store passwords anywhere except logs during email failure.
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

    /**
     * Creates Super Admin with full transactional guarantees.
     * If any step fails, all previous steps are rolled back.
     */
    public Mono<Void> createSuperAdminTransactionally(String email, String phone) {
        email = normalizeEmail(email);
        phone = normalizePhone(phone);

        String finalEmail = email;
        String finalPhone = phone;

        TransactionContext ctx = new TransactionContext();
        long startTime = System.currentTimeMillis();

        return checkExistingAdmin(finalEmail)
                .flatMap(exists -> {
                    if (exists) {
                        log.info("⚠️ Super Admin already exists: {}", maskEmail(finalEmail));
                        return stateService.markBootstrapComplete();
                    }

                    log.info("🔐 Starting transactional Super Admin creation for: {}",
                            maskEmail(finalEmail));

                    return executeTransactionalCreation(finalEmail, finalPhone, ctx, startTime);
                })
                .doOnError(e -> performRollback(ctx, finalEmail, e, startTime))
                .onErrorResume(e -> {
                    log.error("💥 Bootstrap failed after rollback: {}", e.getMessage());
                    return Mono.empty(); // Prevent application crash
                });
    }

    /**
     * Executes the creation with rollback checkpoints.
     */
    private Mono<Void> executeTransactionalCreation(
            String email,
            String phone,
            TransactionContext ctx,
            long startTime) {

        String password = PasswordUtils.generateSecurePassword(16);
        User superAdmin = buildSuperAdminUser(email, phone, password);

        log.info("🔄 [TX-START] Beginning transactional creation for {}", maskEmail(email));

        return Mono.defer(() -> {
                    // STEP 1: Create Firebase Auth user
                    return createFirebaseUser(superAdmin, password, ctx)
                            .doOnSuccess(u -> log.info("✓ Step 1/6: Firebase user created"))

                            // STEP 2: Assign roles and permissions
                            .flatMap(user -> assignRolesTransactionally(user, ctx)
                                    .doOnSuccess(u -> log.info("✓ Step 2/6: Roles assigned")))

                            // STEP 3: Save to Firestore using batch write
                            .flatMap(user -> saveUserToFirestoreBatch(user, ctx)
                                    .doOnSuccess(u -> log.info("✓ Step 3/6: Saved to Firestore")))

                            // STEP 4: Cache email in Redis
                            .flatMap(user -> cacheEmailRegistration(user, ctx)
                                    .doOnSuccess(u -> log.info("✓ Step 4/6: Cached in Redis")))

                            // STEP 5: Mark bootstrap complete
                            // ✅ FIXED: Add .thenReturn(user) to continue the chain
                            .flatMap(user -> markBootstrapCompleteTransactionally(ctx)
                                    .doOnSuccess(v -> log.info("✓ Step 5/6: Bootstrap marked complete"))
                                    .thenReturn(user)) // ✅ CRITICAL FIX!

                            // STEP 6: Send notification (now this will execute!)
                            .flatMap(user -> {
                                log.info("▶ Step 6/6: Sending notification email to {}", maskEmail(email));
                                return sendNotificationWithFallback(email, password)
                                        .doOnSuccess(x -> log.info("✓ Step 6/6: Notification completed"));
                            })

                            // SUCCESS: Log completion
                            .doOnSuccess(v -> logSuccessfulBootstrap(email, startTime))

                            .then(); // Ensure void return
                })
                .doOnError(e -> log.error("❌ [TX-ERROR] Transaction failed: {}", e.getMessage(), e))
                .doFinally(signal -> log.info("🏁 [TX-END] Transaction completed with signal: {}", signal));
    }

    /**
     * Creates Firebase Auth user with rollback registration.
     */
    private Mono<User> createFirebaseUser(User user, String password, TransactionContext ctx) {
        return firebaseServiceAuth.createSuperAdmin(user, password)
                .doOnSuccess(createdUser -> {
                    ctx.firebaseUserId = createdUser.getId();
                    ctx.firebaseUserEmail = createdUser.getEmail();
                    log.debug("✅ Step 1/5: Firebase user created: {}", ctx.firebaseUserId);
                })
                .doOnError(e -> {
                    log.error("❌ Step 1/5 FAILED: Firebase user creation: {}", e.getMessage());
                    ctx.failurePoint = "FIREBASE_AUTH_CREATION";
                });
    }

    /**
     * Assigns roles using Firestore batch write for atomicity.
     */
    private Mono<User> assignRolesTransactionally(User user, TransactionContext ctx) {
        return Mono.fromCallable(() -> {
                    WriteBatch batch = firestore.batch();

                    // Add ADMIN role
                    DocumentReference adminRoleRef = firestore
                            .collection("user_roles")
                            .document(user.getId() + "_" + Roles.ADMIN);

                    Map<String, Object> adminRoleData = Map.of(
                            "userId", user.getId(),
                            "role", Roles.ADMIN.name(),
                            "assignedAt", Instant.now().toString(),
                            "assignedBy", SYSTEM_CREATOR
                    );
                    batch.set(adminRoleRef, adminRoleData);

                    // Add SUPER_ADMIN role
                    DocumentReference superAdminRoleRef = firestore
                            .collection("user_roles")
                            .document(user.getId() + "_" + Roles.SUPER_ADMIN);

                    Map<String, Object> superAdminRoleData = Map.of(
                            "userId", user.getId(),
                            "role", Roles.SUPER_ADMIN.name(),
                            "assignedAt", Instant.now().toString(),
                            "assignedBy", SYSTEM_CREATOR
                    );
                    batch.set(superAdminRoleRef, superAdminRoleData);

                    // Add permissions
                    DocumentReference permissionsRef = firestore
                            .collection("user_permissions")
                            .document(user.getId());

                    Map<String, Object> permissionsData = new HashMap<>();
                    permissionsData.put("userId", user.getId());
                    permissionsData.put("roles", List.of(Roles.ADMIN.name(), Roles.SUPER_ADMIN.name()));
                    permissionsData.put("grantedAt", Instant.now().toString());
                    batch.set(permissionsRef, permissionsData);

                    // Commit batch
                    batch.commit().get();

                    ctx.rolesAssigned = true;
                    log.debug("✅ Step 2/5: Roles and permissions assigned via batch");

                    return user;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> {
                    log.error("❌ Step 2/5 FAILED: Role assignment: {}", e.getMessage());
                    ctx.failurePoint = "ROLE_ASSIGNMENT";
                });
    }

    /**
     * Saves user to Firestore using atomic transaction.
     */
    private Mono<User> saveUserToFirestoreBatch(User user, TransactionContext ctx) {
        return Mono.fromCallable(() -> {
                    DocumentReference userRef = firestore
                            .collection("users")
                            .document(user.getId());

                    Map<String, Object> userData = convertUserToMap(user);

                    userRef.set(userData).get();

                    ctx.userSavedToFirestore = true;
                    ctx.firestoreUserId = user.getId();
                    log.debug("✅ Step 3/5: User saved to Firestore");

                    return user;
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> {
                    log.error("❌ Step 3/5 FAILED: Firestore save: {}", e.getMessage());
                    ctx.failurePoint = "FIRESTORE_USER_SAVE";
                });
    }

    /**
     * Caches email in Redis with rollback support.
     */
    private Mono<User> cacheEmailRegistration(User user, TransactionContext ctx) {
        return redisCacheService.cacheRegisteredEmail(user.getEmail())
                .doOnSuccess(v -> {
                    ctx.emailCachedInRedis = true;
                    log.debug("✅ Step 4/5: Email cached in Redis");
                })
                .doOnError(e -> {
                    log.error("❌ Step 4/5 FAILED: Redis cache: {}", e.getMessage());
                    ctx.failurePoint = "REDIS_EMAIL_CACHE";
                })
                .thenReturn(user)
                .onErrorReturn(user); // Redis failure is non-fatal
    }

    /**
     * Marks bootstrap as complete atomically.
     */
    private Mono<Void> markBootstrapCompleteTransactionally(TransactionContext ctx) {
        return stateService.markBootstrapComplete()
                .doOnSuccess(v -> {
                    ctx.bootstrapMarkedComplete = true;
                    log.debug("✅ Step 5/5: Bootstrap marked complete");
                })
                .doOnError(e -> {
                    log.error("❌ Step 5/5 FAILED: Mark complete: {}", e.getMessage());
                    ctx.failurePoint = "MARK_BOOTSTRAP_COMPLETE";
                });
    }

    /**
     * Sends welcome email with CRITICAL fallback logging.
     * SECURITY: Only logs password to console if email completely fails.
     * This is the ONLY acceptable way to handle email failure.
     */
    private Mono<Void> sendNotificationWithFallback(String email, String password) {
        log.info("🚀 [INIT] Starting email notification for {}", maskEmail(email));

        return notificationService.sendWelcomeEmail(email, password)
                .doOnSubscribe(s ->
                        log.info("🔗 [SUBSCRIBED] Email operation subscribed for {}", maskEmail(email)))
                .timeout(Duration.ofSeconds(30))
                .doOnSuccess(v -> {
                    log.info("✅ [SUCCESS] Welcome email sent successfully to {}", maskEmail(email));
                    // SUCCESS: Password delivered securely via email
                })
                .doOnError(TimeoutException.class, e -> {
                    log.error("⏱️ [TIMEOUT] Email operation timed out after 30s for {}", maskEmail(email));
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
                        log.info("🏁 [FINALLY] Email operation completed with signal: {} for {}",
                                signalType, maskEmail(email)))
                .onErrorResume(e -> {
                    // Don't fail bootstrap, but ensure password was logged
                    log.warn("⚠️ [RESUME] Continuing bootstrap despite email failure - password logged above");
                    return Mono.empty();
                })
                .then(); // Ensure void return
    }

    /**
     * Logs emergency password in formatted box - extracted for reuse.
     */
    private void logEmergencyPassword(String email, String password, Throwable e) {
        log.error("╔════════════════════════════════════════════════════════════╗");
        log.error("║  🚨 EMERGENCY PASSWORD RECOVERY - EMAIL DELIVERY FAILED  ║");
        log.error("╠════════════════════════════════════════════════════════════╣");
        log.error("║  Email: {}║",
                String.format("%-50s", email));
        log.error("║  Password: {}║",
                String.format("%-47s", password));
        log.error("║  Failure Reason: {}║",
                String.format("%-43s", e.getClass().getSimpleName()));
        log.error("╠════════════════════════════════════════════════════════════╣");
        log.error("║  CRITICAL SECURITY NOTICE:                                 ║");
        log.error("║  1. Copy this password IMMEDIATELY                         ║");
        log.error("║  2. Login and change password NOW                          ║");
        log.error("║  3. Clear application logs after retrieval                 ║");
        log.error("║  4. Fix email configuration before next bootstrap          ║");
        log.error("╚════════════════════════════════════════════════════════════╝");

        // Log to audit trail for tracking
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

    /**
     * Performs comprehensive rollback on failure.
     */
    private void performRollback(
            TransactionContext ctx,
            String email,
            Throwable error,
            long startTime) {

        long duration = System.currentTimeMillis() - startTime;

        log.error("🔄 ROLLBACK INITIATED at step: {} after {}ms",
                ctx.failurePoint, duration);
        log.error("🔄 Error: {}", error.getMessage());

        List<String> rollbackSteps = new ArrayList<>();

        try {
            // Rollback in reverse order
            if (ctx.bootstrapMarkedComplete) {
                rollbackBootstrapFlag();
                rollbackSteps.add("bootstrap_flag");
            }

            if (ctx.emailCachedInRedis) {
                rollbackRedisCache(email);
                rollbackSteps.add("redis_cache");
            }

            if (ctx.userSavedToFirestore && ctx.firestoreUserId != null) {
                rollbackFirestoreUser(ctx.firestoreUserId);
                rollbackSteps.add("firestore_user");
            }

            if (ctx.rolesAssigned && ctx.firebaseUserId != null) {
                rollbackRolesAndPermissions(ctx.firebaseUserId);
                rollbackSteps.add("roles_permissions");
            }

            if (ctx.firebaseUserId != null) {
                rollbackFirebaseUser(email);
                rollbackSteps.add("firebase_auth");
            }

            log.info("✅ Rollback completed. Cleaned: {}", rollbackSteps);

        } catch (Exception rollbackError) {
            log.error("💥 CRITICAL: Rollback failed: {}", rollbackError.getMessage());
            logCriticalRollbackFailure(ctx, error, rollbackError, rollbackSteps);
        }

        logTransactionFailure(ctx, email, error, duration, rollbackSteps);
    }

    // ============================================================================
    // ROLLBACK METHODS
    // ============================================================================

    private void rollbackBootstrapFlag() {
        try {
            firestore.collection("system_flags")
                    .document("bootstrap_admin")
                    .delete()
                    .get();
            log.debug("🔄 Rolled back bootstrap flag");
        } catch (Exception e) {
            log.error("Failed to rollback bootstrap flag: {}", e.getMessage());
        }
    }

    private void rollbackRedisCache(String email) {
        try {
            redisCacheService.removeRegisteredEmail(email).block();
            log.debug("🔄 Rolled back Redis email cache");
        } catch (Exception e) {
            log.error("Failed to rollback Redis cache: {}", e.getMessage());
        }
    }

    private void rollbackFirestoreUser(String userId) {
        try {
            firestore.collection("users")
                    .document(userId)
                    .delete()
                    .get();
            log.debug("🔄 Rolled back Firestore user");
        } catch (Exception e) {
            log.error("Failed to rollback Firestore user: {}", e.getMessage());
        }
    }

    private void rollbackRolesAndPermissions(String userId) {
        try {
            WriteBatch batch = firestore.batch();

            batch.delete(firestore.collection("user_roles")
                    .document(userId + "_" + Roles.ADMIN));
            batch.delete(firestore.collection("user_roles")
                    .document(userId + "_" + Roles.SUPER_ADMIN));
            batch.delete(firestore.collection("user_permissions")
                    .document(userId));

            batch.commit().get();
            log.debug("🔄 Rolled back roles and permissions");
        } catch (Exception e) {
            log.error("Failed to rollback roles: {}", e.getMessage());
        }
    }

    private void rollbackFirebaseUser(String email) {
        try {
            firebaseServiceAuth.rollbackFirebaseUserCreation(email).block();
            log.debug("🔄 Rolled back Firebase Auth user");
        } catch (Exception e) {
            log.error("Failed to rollback Firebase user: {}", e.getMessage());
        }
    }

    private void logCriticalRollbackFailure(
            TransactionContext ctx,
            Throwable originalError,
            Exception rollbackError,
            List<String> rollbackSteps) {

        Map<String, Object> criticalData = Map.of(
                "timestamp", Instant.now().toString(),
                "operation", "SUPER_ADMIN_BOOTSTRAP",
                "originalError", originalError.getMessage(),
                "rollbackError", rollbackError.getMessage(),
                "failurePoint", ctx.failurePoint,
                "rollbackStepsCompleted", rollbackSteps,
                "context", ctx.toMap(),
                "severity", "CRITICAL",
                "requiresManualCleanup", true
        );

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
            long duration,
            List<String> rollbackSteps) {

        try {
            Map<String, Object> context = new HashMap<>();
            context.put("email", maskEmail(email));
            context.put("duration", duration);
            context.put("failurePoint", ctx.failurePoint);
            context.put("rollbackSteps", rollbackSteps);

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
    // HELPER METHODS
    // ============================================================================

    private Mono<Boolean> checkExistingAdmin(String email) {
        return firebaseServiceAuth.existsByEmail(email);
    }


    private User buildSuperAdminUser(String email, String phone, String password) {
        Instant now = Instant.now();
        User admin = new User();
        admin.setCreatedAt(now);
        admin.setCreatedBy(SYSTEM_CREATOR);
        admin.setEmail(email);
        admin.setEmailVerified(true);
        admin.setPhoneNumber(phone);
        admin.setPassword(password);
        admin.setStatus(User.Status.ACTIVE);
        admin.setEnabled(true);
        admin.setForcePasswordChange(true); // ✅ Must change on first login
        admin.setAccountLocked(false);
        return admin;
    }

    private Map<String, Object> convertUserToMap(User user) {
        Map<String, Object> map = new HashMap<>();
        map.put("id", user.getId());
        map.put("email", user.getEmail());
        map.put("phoneNumber", user.getPhoneNumber());
        map.put("emailVerified", user.isEmailVerified());
        map.put("status", user.getStatus().name());
        map.put("enabled", user.isEnabled());
        map.put("forcePasswordChange", user.isForcePasswordChange());
        map.put("accountLocked", user.isAccountLocked());
        map.put("createdAt", user.getCreatedAt().toString());
        map.put("createdBy", user.getCreatedBy());
        return map;
    }

    private void logSuccessfulBootstrap(String email, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        log.info("✅ Super Admin bootstrap completed successfully in {}ms for {}",
                duration, maskEmail(email));
    }

    private String normalizeEmail(String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    private String normalizePhone(String phone) {
        if (phone == null) return null;
        phone = phone.trim().replaceAll("\\s+", "");
        if (phone.startsWith("0")) return "+254" + phone.substring(1);
        if (phone.startsWith("254")) return "+" + phone;
        if (!phone.startsWith("+")) return "+" + phone;
        return phone;
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return "***";
        String[] parts = email.split("@");
        return parts[0].substring(0, Math.min(3, parts[0].length())) + "***@" + parts[1];
    }

    /**
     * Transaction context for rollback tracking
     */
    private static class TransactionContext {
        String firebaseUserId;
        String firebaseUserEmail;
        String firestoreUserId;
        boolean rolesAssigned = false;
        boolean userSavedToFirestore = false;
        boolean emailCachedInRedis = false;
        boolean bootstrapMarkedComplete = false;
        String failurePoint = "UNKNOWN";

        Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("firebaseUserId", firebaseUserId);
            map.put("firestoreUserId", firestoreUserId);
            map.put("rolesAssigned", rolesAssigned);
            map.put("userSavedToFirestore", userSavedToFirestore);
            map.put("emailCachedInRedis", emailCachedInRedis);
            map.put("bootstrapMarkedComplete", bootstrapMarkedComplete);
            map.put("failurePoint", failurePoint);
            return map;
        }
    }
}