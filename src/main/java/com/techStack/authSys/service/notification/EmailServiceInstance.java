package com.techStack.authSys.service.notification;

import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Email Service Instance 1
 *
 * Handles all email sending operations with Clock-based timestamp tracking.
 * Provides comprehensive email notifications for authentication events.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceInstance implements EmailService{

    /* =========================
       Dependencies
       ========================= */

    private final JavaMailSender mailSender;
    private final Scheduler emailScheduler;
    private final MetricsService metricsService;
    private final MessageSource messageSource;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${spring.mail.from:${spring.mail.username}}")
    private String fromAddress;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    private static final DateTimeFormatter EMAIL_TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("MMMM dd, yyyy 'at' HH:mm:ss z")
                    .withZone(ZoneId.systemDefault());

    /* =========================
       Core Email Sending
       ========================= */

    /**
     * Internal email sending with Clock-based tracking
     */
    private Mono<Void> sendEmailInternal(String email, String subject, String body) {
        Instant sendStart = clock.instant();

        log.info("📧 Preparing to send email at {} to: {}",
                sendStart, HelperUtils.maskEmail(email));

        return Mono.fromCallable(() -> {
                    log.info("📤 Sending email - To: {}, Subject: {}",
                            HelperUtils.maskEmail(email), subject);

                    SimpleMailMessage message = new SimpleMailMessage();
                    message.setFrom(fromAddress);
                    message.setTo(email);
                    message.setSubject(subject);
                    message.setText(body);

                    mailSender.send(message);

                    Instant sendComplete = clock.instant();
                    Duration sendDuration = Duration.between(sendStart, sendComplete);

                    log.info("✅ Email sent successfully at {} in {} to {}",
                            sendComplete, sendDuration, HelperUtils.maskEmail(email));

                    return null;
                })
                .subscribeOn(emailScheduler)
                .doOnSuccess(__ -> {
                    metricsService.incrementCounter("email.success");
                    metricsService.recordTimer("email.send.duration",
                            Duration.between(sendStart, clock.instant()));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration errorDuration = Duration.between(sendStart, errorTime);

                    log.error("❌ Email failed at {} after {} to {}: {} - {}",
                            errorTime, errorDuration, HelperUtils.maskEmail(email),
                            e.getClass().getSimpleName(), e.getMessage());
                    log.error("❌ Full error:", e);

                    metricsService.incrementCounter("email.failure");
                })
                .onErrorMap(e -> {
                    String errorMsg = String.format("Failed to send email to %s: %s",
                            HelperUtils.maskEmail(email), e.getMessage());
                    return new EmailSendingException(errorMsg, e);
                })
                .then();
    }

    /**
     * Generic email sending method
     */
    public Mono<Void> sendEmail(String email, String subject, String message) {
        log.info("📬 sendEmail called at {} - To: {}, Subject: {}",
                clock.instant(), HelperUtils.maskEmail(email), subject);
        return sendEmailInternal(email, subject, message);
    }

    /* =========================
       Verification Emails
       ========================= */

    /**
     * Send email verification link
     */
    public Mono<Void> sendVerificationEmail(String email, String verificationToken) {
        Instant now = clock.instant();
        String verificationLink = String.format("%s/api/auth/verify-email?token=%s",
                baseUrl, verificationToken);

        String subject = "Verify Your Email Address";
        String body = String.format("""
                Hello,
                
                Thank you for registering! Please verify your email address by clicking the link below:
                
                %s
                
                This link will expire in 24 hours.
                
                If you didn't register for an account, please ignore this email.
                
                Sent at: %s
                
                Best regards,
                The Security Team
                """,
                verificationLink,
                EMAIL_TIMESTAMP_FORMATTER.format(now)
        );

        return sendEmailInternal(email, subject, body);
    }

    /**
     * Send email verification confirmation
     */
    public void sendEmailVerificationConfirmation(String email, Instant verifiedAt) {
        String subject = "Email Verification Successful";
        String body = String.format("""
                Hello,
                
                Your email address has been successfully verified at %s.
                
                You can now access all features of your account.
                
                If you didn't verify your email, please contact support immediately.
                
                Best regards,
                The Security Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(verifiedAt)
        );

        sendEmailInternal(email, subject, body);
    }

    /* =========================
       Registration & Welcome Emails
       ========================= */

    /**
     * Send welcome email to new user
     */
    public Mono<Void> sendWelcomeEmail(String email, String ipAddress) {
        Instant now = clock.instant();

        String subject = "Welcome to Our Platform!";
        String body = String.format("""
                Hello,
                
                Welcome to our platform! We're excited to have you on board.
                
                Your account was created at: %s
                Registration IP: %s
                
                Next steps:
                1. Verify your email address (if not already done)
                2. Complete your profile
                3. Explore our features
                
                For any questions, please contact our support team.
                
                Best regards,
                The Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(now),
                ipAddress
        );

        return sendEmailInternal(email, subject, body);
    }

    /* =========================
       Authentication Event Emails
       ========================= */

    /**
     * Send first login notification
     */
    public Mono<Void> sendFirstLoginNotification(
            String email,
            String ipAddress,
            Instant loginTime) {

        String subject = "Welcome! First Login Detected";
        String body = String.format("""
                Hello,
                
                Welcome! This is your first time logging into your account.
                
                Login Details:
                - Time: %s
                - IP Address: %s
                
                If this wasn't you, please secure your account immediately:
                1. Change your password
                2. Enable two-factor authentication
                3. Contact support
                
                Best regards,
                The Security Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(loginTime),
                ipAddress
        );

        return sendEmailInternal(email, subject, body);
    }

    /* =========================
       Password Management Emails
       ========================= */

    /**
     * Send password reset link
     */
    public Mono<Void> sendPasswordResetEmail(String email, String resetToken) {
        Instant now = clock.instant();
        String resetUrl = String.format("%s/api/auth/reset-password?token=%s",
                baseUrl, resetToken);

        String subject = "Password Reset Request";
        String body = String.format("""
                Hello,
                
                You requested a password reset at %s.
                
                Click the link below to reset your password:
                
                %s
                
                This link will expire in 1 hour.
                
                If you didn't request this, please ignore this email. Your password will remain unchanged.
                
                Best regards,
                The Security Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(now),
                resetUrl
        );

        return sendEmailInternal(email, subject, body);
    }

    /**
     * Send temporary password
     */
    public Mono<Void> sendPasswordResetEmailToTheUser(String email, String tempPassword) {
        Instant now = clock.instant();

        String subject = "Password Reset - Temporary Password";
        String body = String.format("""
                Hello,
                
                Your password was reset at %s.
                
                Temporary Password: %s
                
                IMPORTANT:
                - This password will expire in 24 hours
                - You must change it on your first login
                - Never share this password with anyone
                
                If you didn't request this reset, contact support immediately.
                
                Best regards,
                The Security Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(now),
                tempPassword
        );

        return sendEmailInternal(email, subject, body);
    }

    /**
     * Send password changed notification
     */
    public Mono<Void> sendPasswordChangedNotification(
            String email,
            String ipAddress,
            Instant changedAt,
            boolean forced) {

        String changeType = forced ? "administratively reset" : "changed";

        String subject = "Password Changed - Security Alert";
        String body = String.format("""
                Hello,
                
                Your password was %s at %s.
                
                Change Details:
                - Time: %s
                - IP Address: %s
                - Change Type: %s
                
                If you didn't make this change, your account may be compromised:
                1. Reset your password immediately
                2. Review recent account activity
                3. Enable two-factor authentication
                4. Contact support
                
                Best regards,
                The Security Team
                """,
                changeType,
                EMAIL_TIMESTAMP_FORMATTER.format(changedAt),
                EMAIL_TIMESTAMP_FORMATTER.format(changedAt),
                ipAddress,
                forced ? "Admin-initiated" : "User-initiated"
        );

        return sendEmailInternal(email, subject, body);
    }

    /**
     * Send password expiry warning
     */
    public Mono<Void> sendPasswordExpiryWarning(
            String email,
            int daysRemaining,
            String language) {

        Instant now = clock.instant();

        String subject = messageSource.getMessage(
                "email.password.warning.subject",
                null,
                Locale.forLanguageTag(language)
        );

        String body = String.format("""
                Hello,
                
                Your password will expire in %d days.
                
                Please update your password soon to avoid account interruption.
                
                To change your password:
                1. Log in to your account
                2. Go to Security Settings
                3. Select "Change Password"
                
                Notification sent at: %s
                
                Best regards,
                The Security Team
                """,
                daysRemaining,
                EMAIL_TIMESTAMP_FORMATTER.format(now)
        );

        return sendEmailInternal(email, subject, body);
    }

    /**
     * Send password expired notification
     */
    public Mono<Void> sendPasswordExpiredNotification(
            String email,
            long daysExpired,
            String language) {

        Instant now = clock.instant();

        String subject = messageSource.getMessage(
                "email.password.expired.subject",
                null,
                Locale.forLanguageTag(language)
        );

        String body = String.format("""
                Hello,
                
                Your password expired %d days ago.
                
                You must reset your password immediately to regain access to your account.
                
                To reset your password:
                1. Visit the password reset page
                2. Enter your email address
                3. Follow the instructions in the reset email
                
                Notification sent at: %s
                
                Best regards,
                The Security Team
                """,
                daysExpired,
                EMAIL_TIMESTAMP_FORMATTER.format(now)
        );

        return sendEmailInternal(email, subject, body);
    }

    /* =========================
       Account Security Emails
       ========================= */

    /**
     * Send account locked notification
     */
    public Mono<Void> sendAccountLockedNotification(
            String userId,
            String reason,
            Instant lockedAt) {

        // Note: This method uses userId - you may need to fetch the email first
        // For now, assuming userId can be used to retrieve email

        String subject = "Account Locked - Security Alert";
        String body = String.format("""
                Hello,
                
                Your account has been locked at %s.
                
                Reason: %s
                
                To unlock your account:
                1. Wait for the automatic unlock period
                2. Contact support for immediate assistance
                3. Provide your user ID for verification
                
                Security is our top priority. Thank you for your understanding.
                
                Best regards,
                The Security Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(lockedAt),
                reason
        );

        // Note: You'll need to implement email lookup by userId
        return Mono.empty(); // Placeholder - implement email lookup
    }

    /**
     * Send account locked notification with language support
     */
    public Mono<Void> sendAccountLockedNotification(
            String email,
            String reason,
            String language) {

        Instant now = clock.instant();

        String subject = messageSource.getMessage(
                "email.account.locked.subject",
                null,
                Locale.forLanguageTag(language)
        );

        String body = String.format("""
                Hello,
                
                Your account has been locked due to: %s
                
                Locked at: %s
                
                To resolve this issue:
                1. Review the lock reason above
                2. Contact support if you believe this is an error
                3. Follow any instructions provided
                
                Please contact support for assistance.
                
                Best regards,
                The Security Team
                """,
                reason,
                EMAIL_TIMESTAMP_FORMATTER.format(now)
        );

        return sendEmailInternal(email, subject, body);
    }

    /* =========================
       Approval Workflow Emails
       ========================= */

    /**
     * Send user approved notification
     */
    public Mono<Void> sendUserApprovedNotification(
            String email,
            String approvedBy,
            Instant approvedAt) {

        String subject = "Account Approved - Welcome!";
        String body = String.format("""
                Hello,
                
                Great news! Your account has been approved.
                
                Approval Details:
                - Approved at: %s
                - Approved by: %s
                
                You can now:
                1. Log in to your account
                2. Access all available features
                3. Customize your profile
                
                Welcome aboard!
                
                Best regards,
                The Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(approvedAt),
                approvedBy
        );

        return sendEmailInternal(email, subject, body);
    }

    /**
     * Send user rejected notification
     */
    public Mono<Void> sendUserRejectedNotification(
            String email,
            String reason,
            Instant rejectedAt) {

        String subject = "Account Registration Decision";
        String body = String.format("""
                Hello,
                
                We regret to inform you that your account registration was not approved.
                
                Decision Details:
                - Reviewed at: %s
                - Reason: %s
                
                If you believe this decision was made in error, please contact our support team.
                
                Thank you for your interest.
                
                Best regards,
                The Team
                """,
                EMAIL_TIMESTAMP_FORMATTER.format(rejectedAt),
                reason
        );

        return sendEmailInternal(email, subject, body);
    }
}