package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserFactory;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.notification.EmailServiceInstance;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.util.password.PasswordUtils;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * Admin User Management Service
 *
 * Handles Super Admin-initiated creation of Admin users.
 * Uses standard registration infrastructure for consistency.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminUserManagementService {

    /* =========================
       Dependencies
       ========================= */

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RoleAssignmentService roleAssignmentService;
    private final RedisUserCacheService redisCacheService;
    private final EmailServiceInstance emailService;
    private final AuditLogService auditLogService;
    private final MetricsService metricsService;
    private final JwtService jwtService;
    private final Clock clock;

    /* =========================
       Admin User Creation
       ========================= */

    /**
     * Create a new Admin user (Super Admin only)
     * Uses UserFactory and existing infrastructure for consistency
     */
    public Mono<User> createAdminUser(
            UserRegistrationDTO userDto,
            ServerWebExchange exchange,
            String ipAddress,
            String deviceFingerprint
    ) {
        Instant startTime = clock.instant();

        return extractCreatorId(exchange)
                .flatMap(creatorId -> {
                    log.info("🔐 Super Admin {} creating Admin for: {} at {}",
                            creatorId, HelperUtils.maskEmail(userDto.getEmail()), startTime);

                    return validateAndCreateAdmin(
                            userDto,
                            creatorId,
                            ipAddress,
                            deviceFingerprint,
                            startTime
                    );
                });
    }

    /* =========================
       Validation & Creation
       ========================= */

    /**
     * Validate and create admin user
     */
    private Mono<User> validateAndCreateAdmin(
            UserRegistrationDTO userDto,
            String creatorId,
            String ipAddress,
            String deviceFingerprint,
            Instant startTime
    ) {
        // Generate secure password
        String generatedPassword = PasswordUtils.generateSecurePassword(16);

        return checkEmailAvailability(userDto.getEmail())
                .flatMap(available -> {
                    if (!available) {
                        return Mono.error(new IllegalStateException(
                                "Email already registered: " + userDto.getEmail()));
                    }

                    // Create admin user using UserFactory
                    User adminUser = UserFactory.createAdminUser(
                            userDto.getEmail(),
                            userDto.getFirstName(),
                            userDto.getLastName(),
                            clock
                    );

                    // Set additional properties
                    adminUser.setCreatedBy(creatorId);
                    adminUser.setForcePasswordChange(true);
                    adminUser.setPhoneNumber(userDto.getPhoneNumber());
                    adminUser.setDepartment(userDto.getDepartment());

                    // Create in Firebase and Firestore
                    return createAdminInFirebase(
                            adminUser,
                            generatedPassword,
                            ipAddress,
                            deviceFingerprint,
                            creatorId,
                            startTime
                    );
                })
                .doOnError(e -> handleCreationError(e, userDto.getEmail(), startTime));
    }

    /**
     * Check if email is available
     */
    private Mono<Boolean> checkEmailAvailability(String email) {
        Instant now = clock.instant();

        return redisCacheService.isEmailRegistered(email)
                .map(registered -> !registered)
                .doOnNext(available -> {
                    if (available) {
                        log.debug("Email available: {} at {}",
                                HelperUtils.maskEmail(email), now);
                    } else {
                        log.warn("Email already registered: {} at {}",
                                HelperUtils.maskEmail(email), now);
                    }
                })
                .onErrorReturn(true); // Assume available on cache error
    }

    /* =========================
       Firebase Creation
       ========================= */

    /**
     * Create admin in Firebase and assign roles
     */
    private Mono<User> createAdminInFirebase(
            User adminUser,
            String password,
            String ipAddress,
            String deviceFingerprint,
            String creatorId,
            Instant startTime
    ) {
        return firebaseServiceAuth.createFirebaseUser(
                        adminUser,
                        password,
                        ipAddress,
                        deviceFingerprint
                )
                .flatMap(createdUser ->
                        // Assign roles and permissions
                        roleAssignmentService.assignRolesAndPermissions(
                                createdUser,
                                clock.instant()
                        )
                )
                .flatMap(userWithRoles ->
                        // Post-creation tasks
                        performPostCreationTasks(
                                userWithRoles,
                                password,
                                ipAddress,
                                creatorId,
                                startTime
                        )
                );
    }

    /* =========================
       Post-Creation Tasks
       ========================= */

    /**
     * Perform post-creation tasks (email, audit, metrics)
     */
    private Mono<User> performPostCreationTasks(
            User user,
            String generatedPassword,
            String ipAddress,
            String creatorId,
            Instant startTime
    ) {
        return sendWelcomeEmail(user, generatedPassword)
                .then(cacheRegisteredEmail(user.getEmail()))
                .then(recordSuccessMetrics(user, ipAddress, creatorId, startTime))
                .thenReturn(user);
    }

    /**
     * Send welcome email with temporary credentials
     */
    private Mono<Void> sendWelcomeEmail(User user, String tempPassword) {
        Instant now = clock.instant();

        String subject = "🔐 Your Admin Account Created";
        String body = buildWelcomeEmailBody(user, tempPassword, now);

        return emailService.sendEmail(user.getEmail(), subject, body)
                .doOnSuccess(v -> log.info("✅ Welcome email sent to {} at {}",
                        HelperUtils.maskEmail(user.getEmail()), now))
                .doOnError(e -> log.error("❌ Failed to send welcome email at {}: {}",
                        now, e.getMessage()))
                .onErrorResume(e -> Mono.empty()); // Non-blocking
    }

    /**
     * Build welcome email body
     */
    private String buildWelcomeEmailBody(User user, String tempPassword, Instant timestamp) {
        return String.format("""
                Welcome to the Admin Panel!
                
                Your admin account has been created by a Super Admin at %s.
                
                Account Details:
                - Email: %s
                - Temporary Password: %s
                - Role: ADMIN
                
                IMPORTANT SECURITY STEPS:
                1. Log in and change your password immediately
                2. Enable multi-factor authentication (MFA)
                3. Review your assigned permissions
                4. Familiarize yourself with admin responsibilities
                
                Login URL: https://your-app.com/admin/login
                
                Security Best Practices:
                - Never share your credentials
                - Use a strong, unique password
                - Enable MFA for additional security
                - Log out when not in use
                
                For security questions or concerns, contact the security team.
                
                Best regards,
                The Security Team
                """,
                timestamp,
                user.getEmail(),
                tempPassword
        );
    }

    /**
     * Cache registered email
     */
    private Mono<Void> cacheRegisteredEmail(String email) {
        return redisCacheService.cacheRegisteredEmail(email)
                .doOnSuccess(v -> log.debug("Cached registered email: {}",
                        HelperUtils.maskEmail(email)))
                .onErrorResume(e -> {
                    log.warn("Failed to cache email: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    /**
     * Record success metrics and audit logs
     */
    private Mono<Void> recordSuccessMetrics(
            User user,
            String ipAddress,
            String creatorId,
            Instant startTime
    ) {
        Instant endTime = clock.instant();
        Duration duration = Duration.between(startTime, endTime);

        return Mono.fromRunnable(() -> {
            log.info("✅ Admin created for {} by {} in {} at {}",
                    HelperUtils.maskEmail(user.getEmail()),
                    creatorId,
                    duration,
                    endTime);

            // Audit log (fire and forget)
            auditLogService.logAuditEventBootstrap(
                    user,
                    com.techStack.authSys.models.audit.ActionType.ADMIN_CREATED,
                    String.format("Admin created by Super Admin: %s at %s", creatorId, endTime),
                    ipAddress
            ).subscribe();

            // Metrics
            metricsService.incrementCounter("user.admin.created");
            metricsService.incrementCounter("user.registration.success");
            metricsService.recordTimer("user.admin.creation.time", duration);
        });
    }

    /* =========================
       Error Handling
       ========================= */

    /**
     * Handle creation errors with cleanup
     */
    private void handleCreationError(Throwable e, String email, Instant startTime) {
        Instant now = clock.instant();
        Duration duration = Duration.between(startTime, now);

        log.error("❌ Admin creation failed for {} after {} at {}: {}",
                HelperUtils.maskEmail(email), duration, now, e.getMessage());

        metricsService.incrementCounter("user.admin.creation.failure");

        // Cleanup failed registration
        firebaseServiceAuth.cleanupFailedRegistration(email)
                .doOnSuccess(v -> log.info("Cleaned up failed registration for {} at {}",
                        HelperUtils.maskEmail(email), now))
                .subscribe();
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Extract creator UID from JWT token
     */
    private Mono<String> extractCreatorId(ServerWebExchange exchange) {
        return Mono.justOrEmpty(
                        exchange.getRequest().getHeaders().getFirst("Authorization")
                )
                .map(token -> token.replace("Bearer ", "").trim())
                .flatMap(token -> jwtService.validateToken(token, "access"))
                .map(claims -> (String) claims.get("sub"))
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "Unable to extract creator ID from token")));
    }
}