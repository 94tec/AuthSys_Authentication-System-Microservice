package com.techStack.authSys.service;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.config.AppConfigProperties;
import com.techStack.authSys.models.ActionType;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.util.PasswordUtils;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.apache.commons.lang3.StringUtils;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class BootstrapAdminInitializer implements CommandLineRunner {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RoleAssignmentService roleAssignmentService;
    private final AuditLogService auditLogService;
    private final EmailServiceInstance1 mailService; // your email service
    private final AppConfigProperties appConfigProperties; // optional config-based email/password
    private final BootstrapFlagService bootstrapFlagService;
    private final MetricsService metricsService;

    private void validateConfig() {
        if (StringUtils.isBlank(appConfigProperties.getSuperAdminEmail())) {
            throw new IllegalStateException("Super admin email not configured");
        }
        if (StringUtils.isBlank(appConfigProperties.getSuperAdminPhone())) {
            throw new IllegalStateException("Super admin phone number not configured");
        }
        // Add other validations as needed
    }

    @Override
    public void run(String... args) {
        try {
            validateConfig();
            logger.info("Checking if super admin bootstrap is already completed...");

            Boolean alreadyBootstrapped = bootstrapFlagService.isBootstrapCompleted()
                    .onErrorResume(e -> {
                        logger.error("Error checking bootstrap status", e);
                        return Mono.just(true); // Failsafe: assume it's completed to prevent duplicate creation
                    })
                    .block();

            if (Boolean.TRUE.equals(alreadyBootstrapped)) {
                logger.info("Super admin bootstrap already completed. Skipping initialization...");
                return;
            }
            String email = appConfigProperties.getSuperAdminEmail();
            String phone = appConfigProperties.getSuperAdminPhone();
            String password = generateSecurePassword();

            logger.info("Bootstrapping super admin with email: {}", email);

            firebaseServiceAuth.findByEmail(email)
                    .switchIfEmpty(registerSuperAdmin(email, password, phone)) // Only register if not found
                    .flatMap(user ->

                            bootstrapFlagService.markBootstrapComplete().thenReturn(user)
                    )
                    .doOnSuccess(user ->
                            logger.info("Super admin bootstrap process completed successfully.")
                    )
                    .doOnError(e ->
                            logger.error("Failed to bootstrap super admin", e)
                    )
                    .block();

        } catch (Exception e) {
            logger.error("Critical error during super admin bootstrap", e);
            // Optional: alerting mechanism (e.g., send email/SMS/Slack alert)
        }
    }

    private Mono<User> registerSuperAdmin(String email, String password, String phone) {
        logger.info("Registering super admin user with email: {}  phone: {}", email, phone);
        logger.info("Generated secure password for super admin (masked): {}******", password.substring(0, 6));
        long startTime = System.currentTimeMillis();

        User superAdmin = new User();
        superAdmin.setCreatedAt(Instant.now());
        superAdmin.setCreatedBy("BOOTSTRAP");
        superAdmin.setEmail(email);
        superAdmin.setEmailVerified(true); // since we're bootstrapping
        superAdmin.setPhoneNumber(phone);
        superAdmin.setPassword(password);
        superAdmin.setStatus(User.Status.ACTIVE);
        superAdmin.setForcePasswordChange(true);  // <-- Force reset
        superAdmin.setEnabled(true);

        return firebaseServiceAuth.createSuperAdmin(superAdmin, password)
                .flatMap(firebaseUser -> {
                    // First, assign roles and permissions, then proceed to save the user
                    return roleAssignmentService.assignRoleAndPermissions(superAdmin, Roles.ADMIN)
                            .then(roleAssignmentService.assignRoleAndPermissions(superAdmin, Roles.SUPER_ADMIN))
                            .then(firebaseServiceAuth.saveUserPermissions(firebaseUser))
                            .thenReturn(superAdmin);
                })
                .flatMap(savedUser -> {
                    // After assigning roles, save the user data
                    return firebaseServiceAuth.saveUser(savedUser,"127.0.0.1","SYSTEM")
                            .thenReturn(savedUser); // Proceed with the saved user after saving
                })
                .doOnSuccess(user -> {
                    long duration = System.currentTimeMillis() - startTime;

                    // Chain email sending FIRST
                    mailService.sendEmail(email, "Your Super Admin Account",
                                    STR."Welcome! Your temporary password is: \{password}")
                            .doOnError(e -> logger.error("Failed to send welcome email", e))
                            .onErrorResume(e -> {
                                // Critical: Log audit failure
                                auditLogService.logAudit(
                                        user,
                                        ActionType.EMAIL_FAILURE,
                                        STR."Failed to send welcome email to \{email}",
                                        e.getMessage()
                                );
                                return Mono.empty(); // Continue chain
                            })
                            .subscribe(); // Explicit subscription
                    auditLogService.logAudit(
                            user,
                            ActionType.SUPER_ADMIN_CREATED,
                            STR."Bootstrap super admin created: \{user.getEmail()}",
                            null
                    );
                    metricsService.incrementCounter("user.registration.success");
                    metricsService.recordTimer("user.registration.time", Duration.ofMillis(duration));
                })
                .doOnError(e -> {
                    logger.error("Failed to bootstrap super admin", e);
                    if (e instanceof FirebaseAuthException && "EMAIL_EXISTS".equals(((FirebaseAuthException) e).getErrorCode())) {
                        firebaseServiceAuth.cleanupFailedRegistration(email).subscribe();
                    }
                } )
                .onErrorResume(e -> {
                    logger.error("Error during super admin creation. Initiating rollback for user: {}", email, e);
                    return firebaseServiceAuth.rollbackFirebaseUserCreation(email)
                            .then(Mono.error(e)); // continue to propagate original error after rollback

                });
    }
    private String generateSecurePassword() {
        // Generate a strong password with a length of 16 characters
        return PasswordUtils.generateSecurePassword(16);
    }

}
