package com.techStack.authSys.service.user;

import com.techStack.authSys.models.user.ApprovalLevel;
import com.techStack.authSys.models.user.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;

/**
 * Admin Notification Service
 *
 * Sends email notifications for admin-related events.
 * Uses Clock for timestamp tracking and unified ApprovalLevel enum.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AdminNotificationService {

    /* =========================
       Dependencies
       ========================= */

    private final JavaMailSender mailSender;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${app.admin.email:admin@yourdomain.com}")
    private String adminEmail;

    @Value("${app.admin.superadmin-email:superadmin@yourdomain.com}")
    private String superAdminEmail;

    @Value("${app.admin.manager-email:manager@yourdomain.com}")
    private String managerEmail;

    @Value("${app.name:YourApp}")
    private String appName;

    @Value("${app.url:https://yourdomain.com}")
    private String appUrl;

    @Value("${app.support-email:support@yourdomain.com}")
    private String supportEmail;

    /* =========================
       Approval Notifications
       ========================= */

    /**
     * Notify admins when new user requires approval
     */
    public Mono<Void> notifyAdminsForApproval(User user, ApprovalLevel approvalLevel) {
        Instant now = clock.instant();

        return Mono.fromRunnable(() -> {
            try {
                String recipients = getRecipientsForApprovalLevel(approvalLevel);

                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(recipients.split(","));
                message.setSubject("🔔 New User Registration Requires Approval");
                message.setText(buildApprovalNotificationBody(user, approvalLevel, now));

                mailSender.send(message);

                log.info("📧 Approval notification sent to {} for user {} (level: {}) at {}",
                        recipients, user.getEmail(), approvalLevel.getDisplayName(), now);

            } catch (Exception e) {
                log.error("⚠️ Failed to send approval notification at {}: {}",
                        now, e.getMessage());
                // Don't throw - notifications are non-critical
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Notify user when their account is approved
     */
    public Mono<Void> notifyUserApproved(User user) {
        Instant now = clock.instant();

        return Mono.fromRunnable(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(user.getEmail());
                message.setSubject("✅ Your Account Has Been Approved");
                message.setText(buildUserApprovedBody(user, now));

                mailSender.send(message);

                log.info("📧 Approval confirmation sent to {} at {}", user.getEmail(), now);

            } catch (Exception e) {
                log.error("⚠️ Failed to send approval confirmation at {}: {}",
                        now, e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Notify user when their account is restored
     */
    public Mono<Void> notifyUserRestored(User user) {
        Instant now = clock.instant();

        return Mono.fromRunnable(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(user.getEmail());
                message.setSubject("✅ Your Account Has Been Restored");
                message.setText(buildUserRestoredBody(user, now));

                mailSender.send(message);

                log.info("📧 Account restored confirmation sent to {} at {}",
                        user.getEmail(), now);

            } catch (Exception e) {
                log.error("⚠️ Failed to send account restored confirmation at {}: {}",
                        now, e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Notify user when their account is rejected
     */
    public Mono<Void> notifyUserRejected(User user, String reason) {
        Instant now = clock.instant();

        return Mono.fromRunnable(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(user.getEmail());
                message.setSubject("❌ Account Registration Not Approved");
                message.setText(buildUserRejectedBody(user, reason, now));

                mailSender.send(message);

                log.info("📧 Rejection notification sent to {} at {}", user.getEmail(), now);

            } catch (Exception e) {
                log.error("⚠️ Failed to send rejection notification at {}: {}",
                        now, e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /* =========================
       Recipient Resolution
       ========================= */

    /**
     * Get recipients based on approval level
     * Maps ApprovalLevel to appropriate admin recipients
     */
    private String getRecipientsForApprovalLevel(ApprovalLevel level) {
        // In production, query database for users with required roles
        return switch (level) {
            case PENDING_L2 ->
                // Highest level approval - ADMIN and SUPER_ADMIN
                    adminEmail + "," + superAdminEmail;

            case PENDING_L1 ->
                // Standard approval - MANAGER, ADMIN, and SUPER_ADMIN
                    managerEmail + "," + adminEmail + "," + superAdminEmail;

            case NOT_REQUIRED, APPROVED_L1, APPROVED, REJECTED ->
                // Should not happen, but default to admin
                    adminEmail;
        };
    }

    /* =========================
       Email Body Builders
       ========================= */

    /**
     * Build approval notification body
     */
    private String buildApprovalNotificationBody(
            User user,
            ApprovalLevel level,
            Instant timestamp
    ) {
        return String.format("""
                A new user has registered and requires approval.
                
                User Details:
                - Email: %s
                - Name: %s %s
                - Requested Roles: %s
                - Approval Level Required: %s
                - Registration Date: %s
                
                Please review and approve/reject at:
                %s/admin/users/pending
                
                This is an automated notification sent at %s. Do not reply to this email.
                """,
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getRoles(),
                level.getDisplayName(),
                user.getCreatedAt(),
                appUrl,
                timestamp
        );
    }

    /**
     * Build user approved body
     */
    private String buildUserApprovedBody(User user, Instant timestamp) {
        return String.format("""
                Dear %s,
                
                Great news! Your account has been approved at %s.
                
                You can now log in at: %s/login
                
                Email: %s
                Roles: %s
                
                If you have any questions, please contact support at %s
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                timestamp,
                appUrl,
                user.getEmail(),
                user.getRoles(),
                supportEmail,
                appName
        );
    }

    /**
     * Build user restored body
     */
    private String buildUserRestoredBody(User user, Instant timestamp) {
        return String.format("""
                Dear %s,
                
                Your account has been reinstated and is now pending approval as of %s.
                
                Email: %s
                
                You will receive another notification once your account has been reviewed and approved.
                
                If you have any questions, please contact support at %s
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                timestamp,
                user.getEmail(),
                supportEmail,
                appName
        );
    }

    /**
     * Build user rejected body
     */
    private String buildUserRejectedBody(User user, String reason, Instant timestamp) {
        return String.format("""
                Dear %s,
                
                Unfortunately, your account registration has not been approved as of %s.
                
                Reason: %s
                
                If you believe this is an error or have questions, please contact support at %s
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                timestamp,
                reason != null ? reason : "No specific reason provided",
                supportEmail,
                appName
        );
    }
}