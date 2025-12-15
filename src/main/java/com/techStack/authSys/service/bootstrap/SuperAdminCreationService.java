package com.techStack.authSys.service.bootstrap;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.service.*;
import com.techStack.authSys.util.PasswordUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

/**
 * Handles Super Admin account creation during bootstrap.
 * Ensures idempotent creation with proper error handling and rollback.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SuperAdminCreationService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RoleAssignmentService roleAssignmentService;
    private final BootstrapNotificationService notificationService;
    private final BootstrapStateService stateService;
    private final MetricsService metricsService;

    private static final String SYSTEM_CREATOR = "BOOTSTRAP_SYSTEM";
    private static final String SYSTEM_IP = "127.0.0.1";

    /**
     * Creates Super Admin if it doesn't already exist.
     * Idempotent - safe to call multiple times.
     */
    public Mono<Void> createSuperAdminIfAbsent(String email, String phone) {
        email = normalizeEmail(email);
        phone = normalizePhone(phone);

        String finalEmail = email;
        String finalPhone = phone;

        long startTime = System.currentTimeMillis();

        return checkExistingAdmin(finalEmail)
                .flatMap(exists -> {
                    if (exists) {
                        log.info("⚠️ Super Admin already exists: {}", maskEmail(finalEmail));
                        return stateService.markBootstrapComplete();
                    }

                    log.info("🔐 Creating new Super Admin account: {}", maskEmail(finalEmail));
                    return createSuperAdmin(finalEmail, finalPhone, startTime);
                });
    }

    /**
     * Checks if Super Admin already exists.
     */
    private Mono<Boolean> checkExistingAdmin(String email) {
        return firebaseServiceAuth.existsByEmail(email);
    }

    /**
     * Creates Super Admin with roles, permissions, and notifications.
     */
    private Mono<Void> createSuperAdmin(String email, String phone, long startTime) {
        String password = PasswordUtils.generateSecurePassword(16);
        User superAdmin = buildSuperAdminUser(email, phone, password);

        return firebaseServiceAuth.createSuperAdmin(superAdmin, password)
                .flatMap(firebaseUser -> assignRolesAndPermissions(firebaseUser, superAdmin))
                .flatMap(user -> persistUserData(user, password))
                .flatMap(user -> finalizeBootstrap(user, password, startTime))
                .onErrorResume(e -> handleCreationError(email, e));
    }

    /**
     * Builds Super Admin user object.
     */
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
        admin.setForcePasswordChange(true);
        admin.setAccountLocked(false);

        return admin;
    }

    /**
     * Assigns ADMIN and SUPER_ADMIN roles with their permissions.
     */
    private Mono<User> assignRolesAndPermissions(User firebaseUser, User domainUser) {
        log.debug("🔐 Assigning roles and permissions to Super Admin");

        return Mono.zip(
                        roleAssignmentService.assignRoleAndPermissions(domainUser, Roles.ADMIN),
                        roleAssignmentService.assignRoleAndPermissions(domainUser, Roles.SUPER_ADMIN)
                )
                .flatMap(tuple -> firebaseServiceAuth.saveUserPermissions(firebaseUser))
                .thenReturn(domainUser)
                .doOnSuccess(u -> log.debug("✅ Roles and permissions assigned"))
                .doOnError(e -> log.error("❌ Failed to assign roles: {}", e.getMessage()));
    }

    /**
     * Persists user data to Firestore.
     */
    private Mono<User> persistUserData(User user, String password) {
        return firebaseServiceAuth.saveUser(user, SYSTEM_IP, SYSTEM_CREATOR)
                .thenReturn(user)
                .doOnSuccess(u -> log.debug("✅ User data persisted"))
                .doOnError(e -> log.error("❌ Failed to persist user: {}", e.getMessage()));
    }

    /**
     * Finalizes bootstrap: marks complete, sends email, records metrics.
     */
    private Mono<Void> finalizeBootstrap(User user, String password, long startTime) {
        long duration = System.currentTimeMillis() - startTime;

        return Mono.when(
                        stateService.markBootstrapComplete(),
                        notificationService.sendWelcomeEmail(user.getEmail(), password),
                        recordBootstrapMetrics(user, duration)
                )
                .doOnSuccess(v -> log.info("✅ Super Admin bootstrap completed in {} ms", duration));
    }

    /**
     * Records bootstrap metrics.
     */
    private Mono<Void> recordBootstrapMetrics(User user, long duration) {
        return Mono.fromRunnable(() -> {
            metricsService.incrementCounter("bootstrap.super_admin.created");
            metricsService.incrementCounter("user.registration.success");
            metricsService.recordTimer("bootstrap.creation.time", Duration.ofMillis(duration));

            log.info("📊 Bootstrap metrics recorded");
        });
    }

    /**
     * Handles creation errors with rollback.
     */
    private Mono<Void> handleCreationError(String email, Throwable e) {
        log.error("🚨 Super Admin creation failed for {}: {}", maskEmail(email), e.getMessage(), e);

        // Attempt rollback for duplicate email scenario
        if (e instanceof FirebaseAuthException &&
                "EMAIL_EXISTS".equals(((FirebaseAuthException) e).getAuthErrorCode().name())) {

            log.warn("Email already exists - marking bootstrap complete anyway");
            return stateService.markBootstrapComplete();
        }

        // Rollback Firebase user if it was created
        return firebaseServiceAuth.rollbackFirebaseUserCreation(email)
                .then(Mono.error(e));
    }

    // ============================================================================
    // UTILITY METHODS
    // ============================================================================

    private String normalizeEmail(String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    private String normalizePhone(String phone) {
        if (phone == null) return null;

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
        return parts[0].substring(0, Math.min(3, parts[0].length())) + "***@" + parts[1];
    }
}
