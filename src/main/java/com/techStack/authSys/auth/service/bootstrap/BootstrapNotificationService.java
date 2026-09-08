package com.techStack.authSys.auth.service.bootstrap;

import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.notification.service.EmailServiceInstance;
import com.techStack.authSys.security.audit.ActionType;
import com.techStack.authSys.security.audit.AuditLogService;
import lombok.RequiredArgsConstructor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashMap;
import java.util.Map;

/**
 * Handles notifications related to bootstrap operations.
 * Sends welcome emails and records audit logs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapNotificationService {

    private final EmailServiceInstance emailService;
    private final AuditLogService auditLogService;

    @Value("${app.login-url}")
    private String loginUrl;

    private static final String WELCOME_EMAIL_SUBJECT = "Your Super Admin Account – Damuchi";

    /**
     * Sends a branded HTML welcome email with temporary password.
     */
    public Mono<Void> sendWelcomeEmail(String email, String temporaryPassword) {
        log.info("📨 Preparing HTML welcome email for Super Admin: {}", HelperUtils.maskEmail(email));

        // Build template variables
        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback name
        variables.put("temporaryPassword", temporaryPassword);
        variables.put("loginUrl", loginUrl);

        return emailService.sendTemplatedEmail(
                        email,
                        WELCOME_EMAIL_SUBJECT,
                        "emails/admin/admin-welcome",  // path relative to templates/emails/
                        variables
                )
                .doOnSuccess(v -> {
                    log.info("✅ HTML welcome email sent successfully to {}", HelperUtils.maskEmail(email));
                    logSuccessfulEmailAudit(email);
                })
                .doOnError(e -> {
                    log.error("❌ Failed to send HTML welcome email to {}: {}",
                            HelperUtils.maskEmail(email), e.getMessage(), e);
                    logFailedEmailAudit(email, e);
                })
                .doOnCancel(() ->
                        log.warn("🚫 Email operation cancelled for {}", HelperUtils.maskEmail(email)));
    }

    //

    public Mono<Void> sendPasswordResetLink(String email) {
        log.info("🔄 Sending password reset link to: {}", HelperUtils.maskEmail(email));

        return Mono.fromCallable(() -> {
                    // Generate reset link using Firebase Admin SDK
                    return com.google.firebase.auth.FirebaseAuth.getInstance()
                            .generatePasswordResetLink(email);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(resetLink -> {
                    // Prepare template variables
                    Map<String, Object> variables = new HashMap<>();
                    variables.put("fullName", email.split("@")[0]); // fallback
                    variables.put("resetLink", resetLink);

                    String subject = "Reset Your Super Admin Password";
                    return emailService.sendTemplatedEmail(
                            email,
                            subject,
                            "emails/admin/password-reset-link",
                            variables
                    );
                })
                .doOnSuccess(v -> log.info("✅ Password reset link email sent to {}", HelperUtils.maskEmail(email)))
                .doOnError(e -> log.error("❌ Failed to send password reset link to {}: {}",
                        HelperUtils.maskEmail(email), e.getMessage(), e));
    }

    /**
     * Logs successful email sending to audit trail.
     */
    private void logSuccessfulEmailAudit(String email) {
        try {
            auditLogService.logAuditEventBootstrap(
                    null, // No user object yet
                    ActionType.EMAIL_SENT,
                    String.format("Bootstrap welcome email sent to %s", HelperUtils.maskEmail(email)),
                    "BOOTSTRAP_SYSTEM"
            ).subscribe();
        } catch (Exception e) {
            log.warn("Failed to log email success audit: {}", e.getMessage());
        }
    }

    /**
     * Logs failed email sending to audit trail.
     */
    private void logFailedEmailAudit(String email, Throwable error) {
        try {
            auditLogService.logAuditEventBootstrap(
                    null,
                    ActionType.EMAIL_FAILURE,
                    String.format("Failed to send bootstrap email to %s", HelperUtils.maskEmail(email)),
                    error.getMessage()
            ).subscribe();
        } catch (Exception e) {
            log.warn("Failed to log email failure audit: {}", e.getMessage());
        }
    }

    /**
     * Gets the login URL for the application.
     * In production, this should come from configuration.
     */
    private String getLoginUrl() {
        // TODO: Get from AppConfig
        return "https://your-app.com/login";
    }

}
