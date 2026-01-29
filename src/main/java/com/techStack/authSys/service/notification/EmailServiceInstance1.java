package com.techStack.authSys.service.notification;

import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.util.validation.HelperUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import org.springframework.context.MessageSource;

import java.util.Locale;

@Service
public class EmailServiceInstance1 {
    private static final Logger logger = LoggerFactory.getLogger(EmailServiceInstance1.class);

    private final JavaMailSender mailSender;
    private final Scheduler emailScheduler;
    private final MetricsService metricsService;
    private final MessageSource messageSource;
    private final String fromAddress; // ✅ ADD THIS

    public EmailServiceInstance1(
            JavaMailSender mailSender,
            Scheduler emailScheduler,
            MetricsService metricsService,
            MessageSource messageSource,
            @Value("${spring.mail.from:${spring.mail.username}}") String fromAddress // ✅ ADD THIS
    ) {
        this.mailSender = mailSender;
        this.emailScheduler = emailScheduler;
        this.metricsService = metricsService;
        this.messageSource = messageSource;
        this.fromAddress = fromAddress; // ✅ ADD THIS
    }

    // ✅ FIXED - Unified email sending core with proper error handling
    private Mono<Void> sendEmailInternal(String email, String subject, String body) {
        logger.info("📧 [EMAIL-INTERNAL] Preparing to send email to: {}", HelperUtils.maskEmail(email));

        return Mono.fromCallable(() -> { // ✅ Changed from fromRunnable to fromCallable
                    logger.info("📤 [EMAIL-SEND] Sending email - To: {}, Subject: {}",
                            HelperUtils.maskEmail(email), subject);

                    SimpleMailMessage message = new SimpleMailMessage();
                    message.setFrom(fromAddress); // ✅ ADD THIS - Critical!
                    message.setTo(email);
                    message.setSubject(subject);
                    message.setText(body);

                    mailSender.send(message); // This throws exceptions that we'll catch

                    logger.info("✅ [EMAIL-SENT] JavaMailSender.send() completed for {}",
                            HelperUtils.maskEmail(email));
                    return null; // Return value for Callable
                })
                .subscribeOn(emailScheduler)
                .doOnSuccess(__ -> {
                    logger.info("✅ [EMAIL-SUCCESS] Email successfully sent to {}", HelperUtils.maskEmail(email));
                    metricsService.incrementCounter("email.success");
                })
                .doOnError(e -> {
                    logger.error("❌ [EMAIL-ERROR] Email failed to {}: {} - {}",
                            HelperUtils.maskEmail(email), e.getClass().getSimpleName(), e.getMessage());
                    logger.error("❌ [EMAIL-STACKTRACE] Full error:", e); // ✅ Full stack trace
                    metricsService.incrementCounter("email.failure");
                })
                .onErrorMap(e -> {
                    // ✅ Map to custom exception with context
                    String errorMsg = String.format("Failed to send email to %s: %s",
                            HelperUtils.maskEmail(email), e.getMessage());
                    return new EmailSendingException(errorMsg, e);
                })
                .then();
    }

    // Specific email methods
    public Mono<Void> sendVerificationEmail(String email, String verificationLink) {
        String subject = "Verify Your Email Address";
        String body = String.format(
                "Hello,\n\nThank you for registering! Click below to verify:\n\n%s\n\n"
                        + "Link expires in 24 hours.\n\n"
                        + "Ignore if you didn't register.",
                verificationLink
        );
        return sendEmailInternal(email, subject, body);
    }

    public Mono<Void> sendEmail(String email, String subject, String message) {
        logger.info("📬 [EMAIL-API] sendEmail called - To: {}, Subject: {}",
                HelperUtils.maskEmail(email), subject);
        return sendEmailInternal(email, subject, message);
    }

    public Mono<Void> sendPasswordResetEmail(String email, String token) {
        String resetUrl = "http://localhost:8001/api/auth/users/reset-password?token=" + token;
        String subject = "Password Reset Request";
        String body = String.format(
                "You requested a password reset. Click below:\n\n%s\n\n"
                        + "Ignore if you didn't request this.",
                resetUrl
        );
        return sendEmailInternal(email, subject, body);
    }

    public Mono<Void> sendPasswordResetEmailToTheUser(String email, String tempPassword) {
        String subject = "Password Reset Required";
        String body = String.format(
                "Your password was reset. Use this temporary password:\n\n%s\n\n"
                        + "Expires in 24 hours.",
                tempPassword
        );
        return sendEmailInternal(email, subject, body);
    }

    public Mono<Void> sendWelcomeEmail(String email, String name) {
        String subject = "Welcome to Our Platform!";
        String body = String.format(
                "Hello %s,\n\nWelcome to our platform!\n\n"
                        + "Contact support for any questions.\n\n"
                        + "Best regards,\nThe Team",
                name
        );
        return sendEmailInternal(email, subject, body);
    }

    // Handle password expiry warnings, expiry notifications, and account lock notifications
    public Mono<Void> sendPasswordExpiryWarning(String email, int daysRemaining, String language) {
        String subject = messageSource.getMessage("email.password.warning.subject",
                null, Locale.forLanguageTag(language));
        String body = String.format(
                "Your password will expire in %d days. Please update your password soon.\n\n" +
                        "Best regards,\nThe Team",
                daysRemaining
        );
        return sendEmailInternal(email, subject, body);
    }

    public Mono<Void> sendPasswordExpiredNotification(String email, long daysExpired, String language) {
        String subject = messageSource.getMessage("email.password.expired.subject",
                null, Locale.forLanguageTag(language));
        String body = String.format(
                "Your password expired %d days ago. Please reset it immediately.\n\n" +
                        "Best regards,\nThe Team",
                daysExpired
        );
        return sendEmailInternal(email, subject, body);
    }

    public Mono<Void> sendAccountLockedNotification(String email, String reason, String language) {
        String subject = messageSource.getMessage("email.account.locked.subject",
                null, Locale.forLanguageTag(language));
        String body = String.format(
                "Your account has been locked due to the following reason: %s.\n\n" +
                        "Please contact support.\n\n" +
                        "Best regards,\nThe Team",
                reason
        );
        return sendEmailInternal(email, subject, body);
    }

}