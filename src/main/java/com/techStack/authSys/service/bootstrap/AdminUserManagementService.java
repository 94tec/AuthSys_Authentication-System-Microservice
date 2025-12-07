package com.techStack.authSys.service.bootstrap;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.exception.EmailAlreadyExistsException;
import com.techStack.authSys.models.ActionType;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.service.*;
import com.techStack.authSys.util.PasswordUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Manages Admin user creation by Super Admins.
 * Handles validation, creation, notification, and audit trail.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminUserManagementService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final DeviceVerificationService deviceVerificationService;
    private final RedisCacheService redisCacheService;
    private final EmailServiceInstance1 emailService;
    private final AuditLogService auditLogService;
    private final MetricsService metricsService;
    private final JwtService jwtService;

    /**
     * Creates a new Admin user.
     * Called by Super Admin to provision Admin accounts.
     */
    public Mono<User> createAdminUser(
            UserDTO userDto,
            ServerWebExchange exchange,
            String ipAddress,
            String deviceFingerprint) {

        long startTime = System.currentTimeMillis();

        return extractCreatorId(exchange)
                .flatMap(creatorId -> {
                    log.info("🔐 Super Admin {} creating Admin for: {}",
                            creatorId, maskEmail(userDto.getEmail()));

                    return validateAndCreateAdmin(
                            userDto, creatorId, ipAddress, deviceFingerprint, startTime);
                });
    }

    /**
     * Validates and creates the admin user.
     */
    private Mono<User> validateAndCreateAdmin(
            UserDTO userDto,
            String creatorId,
            String ipAddress,
            String deviceFingerprint,
            long startTime) {

        // Auto-generate secure password
        String generatedPassword = PasswordUtils.generateSecurePassword(16);
        userDto.setPassword(generatedPassword);
        userDto.setForcePasswordChange(true);

        return checkEmailAvailability(userDto.getEmail())
                .flatMap(available -> {
                    if (!available) {
                        return Mono.error(new EmailAlreadyExistsException(userDto.getEmail()));
                    }

                    return proceedWithAdminCreation(
                            userDto, creatorId, ipAddress, deviceFingerprint,
                            generatedPassword, startTime);
                })
                .doOnError(e -> handleCreationError(e, userDto.getEmail(), startTime));
    }

    /**
     * Checks if email is available for registration.
     */
    private Mono<Boolean> checkEmailAvailability(String email) {
        return redisCacheService.isEmailRegistered(email)
                .map(registered -> !registered)
                .onErrorReturn(true); // Assume available on cache error
    }

    /**
     * Creates the admin user with roles and permissions.
     */
    private Mono<User> proceedWithAdminCreation(
            UserDTO userDto,
            String creatorId,
            String ipAddress,
            String deviceFingerprint,
            String generatedPassword,
            long startTime) {

        return firebaseServiceAuth.createFirebaseUser(userDto, ipAddress, deviceFingerprint)
                .flatMap(user -> {
                    user.setDeviceFingerprint(deviceFingerprint);
                    user.setForcePasswordChange(true);
                    user.setCreatedBy(creatorId);

                    return deviceVerificationService.saveUserFingerprint(user.getId(), deviceFingerprint)
                            .then(sendWelcomeEmail(user, generatedPassword))
                            .then(recordSuccessMetrics(user, ipAddress, creatorId, startTime))
                            .thenReturn(user);
                });
    }

    /**
     * Sends welcome email with temporary credentials.
     */
    private Mono<Void> sendWelcomeEmail(User user, String tempPassword) {
        String subject = "🔐 Your Admin Account Created";
        String body = String.format("""
                Welcome to the Admin Panel!
                
                Your account has been created by a Super Admin.
                
                Email: %s
                Temporary Password: %s
                
                IMPORTANT:
                - Log in and change your password immediately
                - Enable multi-factor authentication
                - Review your assigned permissions
                
                Login URL: https://your-app.com/admin/login
                
                For security questions, contact the security team.
                
                Best regards,
                The Security Team
                """, user.getEmail(), tempPassword);

        return Mono.fromRunnable(() ->
                emailService.sendEmail(user.getEmail(), subject, body)
                        .doOnSuccess(v -> log.info("✅ Welcome email sent to {}",
                                maskEmail(user.getEmail())))
                        .doOnError(e -> log.error("❌ Failed to send welcome email: {}",
                                e.getMessage()))
                        .subscribe()
        );
    }

    /**
     * Records metrics and audit logs for successful creation.
     */
    private Mono<Void> recordSuccessMetrics(
            User user,
            String ipAddress,
            String creatorId,
            long startTime) {

        long duration = System.currentTimeMillis() - startTime;

        return Mono.fromRunnable(() -> {
            log.info("✅ Admin registration completed for {} in {} ms",
                    maskEmail(user.getEmail()), duration);

            // Audit log
            auditLogService.logAudit(
                    user,
                    ActionType.ADMIN_CREATED,
                    String.format("Admin created by Super Admin: %s", creatorId),
                    ipAddress
            ).subscribe();

            // Cache email
            redisCacheService.cacheRegisteredEmail(user.getEmail()).subscribe();

            // Metrics
            metricsService.incrementCounter("user.admin.created");
            metricsService.incrementCounter("user.registration.success");
            metricsService.recordTimer("user.admin.creation.time", Duration.ofMillis(duration));
        });
    }

    /**
     * Handles creation errors with cleanup.
     */
    private void handleCreationError(Throwable e, String email, long startTime) {
        long duration = System.currentTimeMillis() - startTime;

        log.error("❌ Admin registration failed for {} after {} ms: {}",
                maskEmail(email), duration, e.getMessage());

        metricsService.incrementCounter("user.admin.creation.failure");

        // Cleanup if Firebase user was created
        if (e instanceof FirebaseAuthException &&
                "EMAIL_EXISTS".equals(((FirebaseAuthException) e).getAuthErrorCode().name())) {

            firebaseServiceAuth.cleanupFailedRegistration(email)
                    .doOnSuccess(v -> log.info("Cleaned up failed registration for {}",
                            maskEmail(email)))
                    .subscribe();
        }
    }

    /**
     * Extracts creator UID from JWT token.
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

    /**
     * Masks email for logging (GDPR compliance).
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "***";
        }
        String[] parts = email.split("@");
        return parts[0].substring(0, Math.min(3, parts[0].length())) + "***@" + parts[1];
    }
}
