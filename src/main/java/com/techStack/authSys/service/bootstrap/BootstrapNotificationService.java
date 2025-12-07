package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.models.ActionType;
import com.techStack.authSys.service.AuditLogService;
import com.techStack.authSys.service.EmailServiceInstance1;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Handles notifications related to bootstrap operations.
 * Sends welcome emails and records audit logs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapNotificationService {

    private final EmailServiceInstance1 emailService;
    private final AuditLogService auditLogService;

    private static final String WELCOME_EMAIL_SUBJECT = "Your Super Admin Account";
    private static final String WELCOME_EMAIL_TEMPLATE = """
            Welcome to the Admin Panel!
            
            Your Super Admin account has been created successfully.
            
            Temporary Password: %s
            
            IMPORTANT SECURITY NOTICE:
            - This is a temporary password
            - You MUST change it immediately after your first login
            - Do not share this password with anyone
            - This email will be the only time this password is sent
            
            Login URL: %s
            
            For security reasons, please:
            1. Log in within 24 hours
            2. Change your password immediately
            3. Enable multi-factor authentication
            
            If you did not expect this email, please contact support immediately.
            
            Best regards,
            Security Team
            """;

    /**
     * Sends welcome email with temporary password to Super Admin.
     * Non-blocking, logs audit trail on both success and failure.
     */
    public Mono<Void> sendWelcomeEmail(String email, String temporaryPassword) {
        log.info("📨 Sending welcome email to Super Admin: {}", maskEmail(email));

        String emailBody = buildEmailBody(temporaryPassword);

        return emailService.sendEmail(email, WELCOME_EMAIL_SUBJECT, emailBody)
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(v -> {
                    log.info("✅ Welcome email sent successfully to {}", maskEmail(email));
                    logSuccessfulEmailAudit(email);
                })
                .doOnError(e -> {
                    log.error("❌ Failed to send welcome email to {}: {}",
                            maskEmail(email), e.getMessage());
                    logFailedEmailAudit(email, e);
                })
                .onErrorResume(e -> {
                    // Don't fail bootstrap if email fails
                    log.warn("⚠️ Continuing bootstrap despite email failure");
                    return Mono.empty();
                })
                .then();
    }

    /**
     * Builds the email body with the temporary password.
     */
    private String buildEmailBody(String temporaryPassword) {
        String loginUrl = getLoginUrl();
        return String.format(WELCOME_EMAIL_TEMPLATE, temporaryPassword, loginUrl);
    }

    /**
     * Logs successful email sending to audit trail.
     */
    private void logSuccessfulEmailAudit(String email) {
        try {
            auditLogService.logAudit(
                    null, // No user object yet
                    ActionType.EMAIL_SENT,
                    String.format("Bootstrap welcome email sent to %s", maskEmail(email)),
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
            auditLogService.logAudit(
                    null,
                    ActionType.EMAIL_FAILURE,
                    String.format("Failed to send bootstrap email to %s", maskEmail(email)),
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
