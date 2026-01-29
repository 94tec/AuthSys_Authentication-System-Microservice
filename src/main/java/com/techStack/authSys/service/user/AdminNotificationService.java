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

@Service
public class AdminNotificationService {
    private static final Logger logger = LoggerFactory.getLogger(AdminNotificationService.class);

    private final JavaMailSender mailSender;
    private final String adminEmail = "admin@yourdomain.com"; // Configure via properties

    public AdminNotificationService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * Notify admins when new user requires approval
     * Follows document recommendation: "Send notification/alert to admins for manual approval"
     */
    public Mono<Void> notifyAdminsForApproval(User user, ApprovalLevel approvalLevel) {
        return Mono.fromRunnable(() -> {
            try {
                String recipients = getRecipientsForApprovalLevel(approvalLevel);

                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(recipients);
                message.setSubject("🔔 New User Registration Requires Approval");
                message.setText(buildApprovalNotificationBody(user, approvalLevel));

                mailSender.send(message);

                logger.info("📧 Approval notification sent to {} for user {}",
                        recipients, user.getEmail());

            } catch (Exception e) {
                // Log but don't fail registration
                logger.error("⚠️ Failed to send approval notification: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Notify user when their account is approved
     */
    public Mono<Void> notifyUserApproved(User user) {
        return Mono.fromRunnable(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(user.getEmail());
                message.setSubject("✅ Your Account Has Been Approved");
                message.setText(buildUserApprovedBody(user));

                mailSender.send(message);

                logger.info("📧 Approval confirmation sent to {}", user.getEmail());

            } catch (Exception e) {
                logger.error("⚠️ Failed to send approval confirmation: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
    /**
     * Notify user when their account is approved
     */
    public Mono<Void> notifyUserRestored(User user) {
        return Mono.fromRunnable(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(user.getEmail());
                message.setSubject("✅ Your Account Has Been restored ");
                message.setText(buildUserApprovedBody(user));

                mailSender.send(message);

                logger.info("📧 Hello %s, your account has been reinstated and is now pending approval. {}", user.getEmail());

            } catch (Exception e) {
                logger.error("⚠️ Failed to send account restored confirmation: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
    /**
     * Notify user when their account is rejected
     */
    public Mono<Void> notifyUserRejected(User user, String reason) {
        return Mono.fromRunnable(() -> {
            try {
                SimpleMailMessage message = new SimpleMailMessage();
                message.setTo(user.getEmail());
                message.setSubject("❌ Account Registration Not Approved");
                message.setText(buildUserRejectedBody(user, reason));

                mailSender.send(message);

                logger.info("📧 Rejection notification sent to {}", user.getEmail());

            } catch (Exception e) {
                logger.error("⚠️ Failed to send rejection notification: {}", e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

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

    private String buildApprovalNotificationBody(User user, ApprovalLevel level) {
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
                
                This is an automated notification. Do not reply to this email.
                """,
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getRoles(),
                level,
                user.getCreatedAt()
        );
    }

    private String buildUserApprovedBody(User user) {
        return String.format("""
                Dear %s,
                
                Great news! Your account has been approved.
                
                You can now log in at: https://yourdomain.com/login
                
                Email: %s
                Roles: %s
                
                If you have any questions, please contact support.
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                user.getEmail(),
                user.getRoles(),
                "YourApp"
        );
    }

    private String buildUserRejectedBody(User user, String reason) {
        return String.format("""
                Dear %s,
                
                Unfortunately, your account registration has not been approved.
                
                Reason: %s
                
                If you believe this is an error or have questions, please contact support at support@yourdomain.com
                
                Best regards,
                The %s Team
                """,
                user.getFirstName(),
                reason,
                "YourApp"
        );
    }
}
