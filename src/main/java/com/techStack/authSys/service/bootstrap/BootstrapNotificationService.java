package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.notification.EmailServiceInstance;
import com.techStack.authSys.util.validation.HelperUtils;
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

    private final EmailServiceInstance emailService;
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
     * Returns Mono that completes only after email is sent or fails gracefully.
     */
    public Mono<Void> sendWelcomeEmail(String email, String temporaryPassword) {
        log.info("📨 [START] Preparing welcome email for Super Admin: {}", HelperUtils.maskEmail(email));

        // ✅ SIMPLIFIED - Remove double subscribeOn, let EmailService handle it
        return Mono.fromCallable(() -> buildEmailBody(temporaryPassword))
                .doOnNext(body -> log.info("🔨 [BUILD] Email body built for {}", HelperUtils.maskEmail(email)))
                .flatMap(emailBody -> {
                    log.info("📤 [SEND] Calling email service for {}", HelperUtils.maskEmail(email));
                    return emailService.sendEmail(email, WELCOME_EMAIL_SUBJECT, emailBody);
                })
                .doOnSubscribe(s ->
                        log.info("🔗 [SUBSCRIBE] Email service subscribed for {}", HelperUtils.maskEmail(email)))
                .doOnSuccess(v -> {
                    log.info("✅ [SUCCESS] Welcome email sent successfully to {}", HelperUtils.maskEmail(email));
                    logSuccessfulEmailAudit(email);
                })
                .doOnError(e -> {
                    log.error("❌ [ERROR] Failed to send welcome email to {}: {}",
                            HelperUtils.maskEmail(email), e.getMessage(), e);
                    logFailedEmailAudit(email, e);
                })
                .doOnCancel(() ->
                        log.warn("🚫 [CANCEL] Email operation cancelled for {}", HelperUtils.maskEmail(email)))
                .doFinally(signal ->
                        log.info("🏁 [FINALLY] Email operation terminated with signal: {} for {}",
                                signal, HelperUtils.maskEmail(email)));
    }
    public Mono<Void> sendPasswordResetLink(String email) {
        log.info("🔄 Sending password reset link to: {}", HelperUtils.maskEmail(email));

        return Mono.fromCallable(() -> {
            try {
                String resetLink = com.google.firebase.auth.FirebaseAuth.getInstance()
                        .generatePasswordResetLink(email);

                String subject = "Reset Your Super Admin Password";
                String body = String.format("""
                    Hello,
                    
                    A password reset was requested for your Super Admin account.
                    
                    Click the link below to reset your password:
                    %s
                    
                    This link expires in 1 hour.
                    
                    If you didn't request this, please ignore this email.
                    
                    Best regards,
                    Security Team
                    """, resetLink);

                emailService.sendEmail(email, subject, body).block();
                return null;
            } catch (Exception e) {
                throw new RuntimeException("Failed to send password reset link", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
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
