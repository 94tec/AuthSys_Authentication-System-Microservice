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
import reactor.core.scheduler.Schedulers;

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
    private final BootstrapCoordinatorService bootstrapCoordinator;

    @Override
    public void run(String... args) {
        logger.info("🟢 Checking Super Admin bootstrap status...");

        if (!validateConfig()) {
            logger.error("❌ Bootstrap configuration invalid — skipping startup bootstrap.");
            metricsService.incrementCounter("bootstrap.config.invalid");
            return;
        }

        bootstrapCoordinator.acquireBootstrapLock()
                .flatMap(locked -> locked
                        ? performBootstrap()
                        : bootstrapCoordinator.waitForBootstrapCompletion()
                )
                .timeout(Duration.ofMinutes(10)) // prevent infinite hangs
                .doOnSuccess(v -> logger.info("✅ Super Admin bootstrap completed successfully"))
                .doOnError(e -> {
                    logger.error("💥 Bootstrap process failed: {}", e.getMessage(), e);
                    metricsService.incrementCounter("bootstrap.failure");
                })
                .doFinally(signal -> bootstrapCoordinator.releaseBootstrapLock())
                .subscribe();
    }
    private boolean validateConfig() {
        String email = appConfigProperties.getSuperAdminEmail();
        String phone = appConfigProperties.getSuperAdminPhone();
        if (StringUtils.isBlank(email) || StringUtils.isBlank(phone)) return false;
        return email.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    private Mono<Void> performBootstrap() {
        return bootstrapFlagService.isBootstrapCompleted()
                .flatMap(alreadyBootstrapped -> {
                    if (alreadyBootstrapped) {
                        logger.info("✅ Bootstrap previously completed — skipping.");
                        return Mono.empty();
                    }
                    return createSuperAdminIfAbsent();
                });
    }

    private Mono<Void> createSuperAdminIfAbsent() {
        String email = appConfigProperties.getSuperAdminEmail().trim().toLowerCase();
        String phone = normalizePhone(appConfigProperties.getSuperAdminPhone());
        String password = PasswordUtils.generateSecurePassword(16);
        long start = System.currentTimeMillis();

        return firebaseServiceAuth.findByEmail(email)
                .flatMap(existing -> {
                    logger.info("⚠️ Super Admin already exists in Firebase: {}", email);
                    return bootstrapFlagService.markBootstrapComplete();
                })
                .switchIfEmpty(
                        Mono.defer(() -> createSuperAdminFlow(email, phone, password, start))
                )
                .onErrorResume(this::handleBootstrapError);
    }
    private Mono<Void> createSuperAdminFlow(String email, String phone, String password, long start) {
        User user = buildSuperAdmin(email, phone, password);
        logger.info("🔐 Creating Super Admin: {}", email);

        return firebaseServiceAuth.createSuperAdmin(user, password)
                .flatMap(firebaseUser -> Mono.zip(
                        roleAssignmentService.assignRoleAndPermissions(user, Roles.ADMIN),
                        roleAssignmentService.assignRoleAndPermissions(user, Roles.SUPER_ADMIN),
                        firebaseServiceAuth.saveUserPermissions(firebaseUser),
                        firebaseServiceAuth.saveUser(user, "127.0.0.1", "BOOTSTRAP_SYSTEM")
                ).thenReturn(user))
                .flatMap(created -> finalizeBootstrap(created, password, start))
                .onErrorResume(e -> handleCreationError(email, e));
    }

    private User buildSuperAdmin(String email, String phone, String password) {
        User admin = new User();
        admin.setCreatedAt(Instant.now());
        admin.setCreatedBy("BOOTSTRAP_SYSTEM");
        admin.setEmail(email);
        admin.setEmailVerified(true);
        admin.setPhoneNumber(phone);
        admin.setPassword(password);
        admin.setStatus(User.Status.ACTIVE);
        admin.setEnabled(true);
        admin.setForcePasswordChange(true);
        return admin;
    }
    private Mono<Void> finalizeBootstrap(User user, String password, long start) {
        return Mono.when(
                        bootstrapFlagService.markBootstrapComplete(),
                        sendBootstrapEmail(user.getEmail(), password),
                        logAuditAndMetrics(user, start)
                )
                .then(Mono.fromRunnable(() ->
                        metricsService.incrementCounter("bootstrap.success")
                ));
    }

    private Mono<Void> sendBootstrapEmail(String email, String password) {
        // Mask password fully in logs for security
        return mailService.sendEmail(email,
                        "Your Super Admin Account",
                        STR."Welcome! Please reset your password immediately. Temporary password: [SECURELY STORED] \{password}")
                .doOnSubscribe(sub -> logger.info("📨 Sending Super Admin welcome email to {}", email))
                .doOnError(e -> logger.error("❌ Email sending failed for {}: {}", email, e.getMessage(), e))
                .onErrorResume(e ->
                        auditLogService.logAudit(null, ActionType.EMAIL_FAILURE,
                                        STR."Failed to send Super Admin email to \{email}", e.getMessage())
                                .then(Mono.empty())
                )
                .subscribeOn(Schedulers.boundedElastic()) // avoid blocking main thread
                .then();
    }

    private Mono<Void> logAuditAndMetrics(User user, long startTime) {
        long duration = System.currentTimeMillis() - startTime;
        return auditLogService.logAudit(
                        user,
                        ActionType.SUPER_ADMIN_CREATED,
                        STR."Bootstrap Super Admin created: \{user.getEmail()}",
                        null
                )
                .then(Mono.fromRunnable(() -> {
                    metricsService.incrementCounter("user.registration.success");
                    metricsService.recordTimer("user.registration.time", Duration.ofMillis(duration));
                    logger.info("✅ Super Admin bootstrap completed in {} ms", duration);
                }));
    }

    private Mono<Void> handleCreationError(String email, Throwable e) {
        logger.error("🚨 Error creating Super Admin [{}]: {}", email, e.getMessage(), e);
        Mono<Void> rollback = firebaseServiceAuth.rollbackFirebaseUserCreation(email);
        if (e instanceof FirebaseAuthException firebaseError && "EMAIL_EXISTS".equals(firebaseError.getErrorCode())) {
            rollback = bootstrapFlagService.markBootstrapComplete();
        }
        return rollback.then(Mono.error(e));
    }

    private Mono<Void> handleBootstrapError(Throwable e) {
        logger.error("💥 Bootstrap fatal error: {}", e.getMessage(), e);
        return Mono.empty();
    }
    private String normalizePhone(String phone) {
        if (StringUtils.isBlank(phone)) return null;
        phone = StringUtils.deleteWhitespace(phone);
        if (phone.startsWith("0")) return "+254" + phone.substring(1);
        if (phone.startsWith("254")) return "+" + phone;
        if (!phone.startsWith("+")) return "+" + phone;
        return phone;
    }

}
