package com.techStack.authSys.service.user;

import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.authorization.RoleAssignmentService.ApprovalLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * Uses Clock for timestamp tracking.
 */
@Service
public class AdminNotificationService {

    private static final Logger logger = LoggerFactory.getLogger(AdminNotificationService.class);

    private final JavaMailSender mailSender;
    private final Clock clock;
    private final String adminEmail = "admin@yourdomain.com"; // Configure via properties

    public AdminNotificationService(JavaMailSender mailSender, Clock clock) {
        this.mailSender = mailSender;
        this.clock = clock;
    }

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
                message.setTo(recipients);
                message.setSubject("🔔 New User Registration Requires Approval");
                message.setText(buildApprovalNotificationBody(user, approvalLevel, now));

                mailSender.send(message);

                logger.info("📧 Approval notification sent to {} for user {} at {}",
                        recipients, user.getEmail(), now);

            } catch (Exception e) {
                logger.error("⚠️ Failed to send approval notification at {}: {}",
                        now, e.getMessage());
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

                logger.info("📧 Approval confirmation sent to {} at {}", user.getEmail(), now);

            } catch (Exception e) {
                logger.error("⚠️ Failed to send approval confirmation at {}: {}",
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

                logger.info("📧 Account restored confirmation sent to {} at {}",
                        user.getEmail(), now);

            } catch (Exception e) {
                logger.error("⚠️ Failed to send account restored confirmation at {}: {}",
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

                logger.info("📧 Rejection notification sent to {} at {}", user.getEmail(), now);

            } catch (Exception e) {
                logger.error("⚠️ Failed to send rejection notification at {}: {}",
                        now, e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /* =========================
       Recipient Resolution
       ========================= */

    /**
     * Get recipients based on approval level
     */
    private String getRecipientsForApprovalLevel(ApprovalLevel level) {
        // In production, query database for users with required roles
        switch (level) {
            case SUPER_ADMIN_ONLY:
                return "superadmin@yourdomain.com";
            case ADMIN_OR_SUPER_ADMIN:
                return "admin@yourdomain.com,superadmin@yourdomain.com";
            case MANAGER_OR_ABOVE:
                return "manager@yourdomain.com,admin@yourdomain.com,superadmin@yourdomain.com";
            default:
                return adminEmail;
        }
    }

    /* =========================
       Email Body Builders
       ========================= */

    /**
     * Build approval notification body
     */
    private String buildApprovalNotificationBody(User user, ApprovalLevel level, Instant timestamp) {
        return String.format("""
                A new user has registered and requires approval.
                
                User Details:
                - Email: %s
                - Name: %s %s
                - Requested Roles: %s
                - Approval Level Required: %s
                - Registration Date: %s
                
                Please review and approve/reject at:
                https://yourdomain.com/admin/users/pending
                
                This is an automated notification sent at %s. Do not reply to this email.
                """,
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getRoles(),
                level,
                user.getCreatedAt(),
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
                
                You can now log in at: https://yourdomain.com/login
                
                Email: %s
                Roles: %s
                
                If you have any questions, please contact support.
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                timestamp,
                user.getEmail(),
                user.getRoles(),
                "YourApp"
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
                
                If you have any questions, please contact support.
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                timestamp,
                user.getEmail(),
                "YourApp"
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
                
                If you believe this is an error or have questions, please contact support at support@yourdomain.com
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                timestamp,
                reason,
                "YourApp"
        );
    }
}
