package com.techStack.authSys.notification.service;

import com.techStack.authSys.auth.exception.EmailSendingException;
import com.techStack.authSys.notification.repository.EmailService;
import jakarta.annotation.PostConstruct;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Email Service Instance
 *
 * Handles all email sending operations with Clock-based timestamp tracking.
 * Provides comprehensive email notifications for authentication events.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceInstance implements EmailService {

    /* =========================
       Dependencies
       ========================= */

    private final JavaMailSender mailSender;
    private final SpringTemplateEngine templateEngine;
    private final Scheduler emailScheduler;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${spring.mail.from:${spring.mail.username}}")
    private String fromAddress;

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${app.frontend-base-url}")
    private String frontendBaseUrl;

    @Value("${app.logo-url}")
    private String logoUrl;

    @Value("${app.logo.cid}")
    private String logoCid;

    @PostConstruct
    public void init() {
        // Use CID for all emails
        this.logoUrl = "cid:" + logoCid;
    }

    private static final DateTimeFormatter EMAIL_TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("MMMM dd, yyyy 'at' HH:mm:ss z")
                    .withZone(ZoneId.systemDefault());

    /* =========================
       Core Email Sending
       ========================= */
    // Core method: send templated email
    public Mono<Void> sendTemplatedEmail(String to, String subject, String templatePath, Map<String, Object> variables) {
        return Mono.fromCallable(() -> {
                    if (!variables.containsKey("logoUrl")) {
                        variables.put("logoUrl", logoUrl);
                    }
                    variables.put("baseUrl", baseUrl);
                    variables.put("subject", subject);
                    variables.put("timestamp", clock.instant());

                    // Render HTML
                    Context context = new Context(Locale.ENGLISH, variables);
                    String htmlContent = templateEngine.process(templatePath, context);

                    // Build MimeMessage
                    MimeMessage mimeMessage = mailSender.createMimeMessage();
                    MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
                    helper.setFrom(fromAddress);
                    helper.setTo(to);
                    helper.setSubject(subject);
                    helper.setText(htmlContent, true); // true = HTML

                    // ✅ Embed the logo using the same CID that was put in the context
                    String cid = (String) variables.get("logoUrl");
                    if (cid != null && cid.startsWith("cid:")) {
                        cid = cid.substring(4); // remove "cid:" prefix
                        ClassPathResource logoResource = new ClassPathResource("static/images/logo.png");
                        helper.addInline(cid, logoResource);
                    }

                    // Send
                    mailSender.send(mimeMessage);
                    return null;
                })
                .subscribeOn(emailScheduler)
                .doOnSuccess(v -> log.info("✅ Templated email sent to {}", to))
                .doOnError(e -> log.error("❌ Failed to send templated email", e))
                .onErrorMap(e -> new EmailSendingException("Failed to send templated email", e))
                .then();
    }

    /* =========================
       Verification Emails
       ========================= */
    /**
     * Send email verification link.
     * The link points to the frontend verification page, which then calls the backend API.
     */
    @Override
    public Mono<Void> sendVerificationEmail(
            String email,
            String verificationToken
    ) {
        Map<String, Object> vars = new HashMap<>();

        String verificationLink = UriComponentsBuilder
                .fromUriString(frontendBaseUrl)
                .path("/verify-email")
                .queryParam("token", verificationToken)
                .build()
                .encode()
                .toUriString();

        vars.put("verificationLink", verificationLink);

        vars.put(
                "fullName",
                email.substring(0, email.indexOf('@'))
        );

        return sendTemplatedEmail(
                email,
                "Verify Your Email",
                "emails/auth/verify-email",
                vars
        );
    }

    /**
     * Send email verification confirmation as a branded HTML email.
     * Returns Mono<Void> for reactive composition.
     */
    public void sendEmailVerificationConfirmation(String email, Instant verifiedAt) {
        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback name
        variables.put("loginUrl", baseUrl + "/login");

        String subject = "Email Verified – Damuchi";
        sendTemplatedEmail(email, subject, "emails/auth/email-verified", variables);
    }

    /* =========================
       Registration & Welcome Emails
       ========================= */
    /**
     * Send welcome email to new user
     */
    @Override
    public Mono<Void> sendWelcomeEmail(String email, String ipAddress) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", email.split("@")[0]);
        vars.put("dashboardUrl", baseUrl + "/dashboard");
        return sendTemplatedEmail(email, "Welcome to Damuchi!", "emails/auth/welcome-email", vars);
    }

    /* =========================
       Authentication Event Emails
       ========================= */
    /**
     * Send first login notification as a branded HTML email.
     */
    @Override
    public Mono<Void> sendFirstLoginNotification(
            String email,
            String ipAddress,
            Instant loginTime) {

        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback name
        variables.put("ipAddress", ipAddress != null ? ipAddress : "Unknown");
        variables.put("loginTime", loginTime);
        variables.put("dashboardUrl", baseUrl + "/dashboard");

        String subject = "Welcome! First Login Detected";
        return sendTemplatedEmail(
                email,
                subject,
                "emails/auth/first-login-notification",
                variables
        );
    }
    // send otp notification

    @Override
    public Mono<Void> sendOtpNotification(String email, String fullName, String purpose, String otp, Instant sentAt) {

        String subject = "OTP for " + purpose;

        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", fullName != null ? fullName : email.split("@")[0]);
        variables.put("purpose", purpose != null ? purpose : "authentication");
        variables.put("otp", otp);
        variables.put("validityMinutes", 10); // configurable
        variables.put("sentAt", sentAt);

        return sendTemplatedEmail(
                email,
                subject,
                "emails/auth/otp-notification",
                variables
        );
    }

    /* =========================
       Password Management Emails
       ========================= */

    /**
     * Send password reset link
     */
    @Override
    public Mono<Void> sendPasswordResetEmail(String email, String resetToken) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("resetLink", baseUrl + "/api/auth/reset-password?token=" + resetToken);
        return sendTemplatedEmail(email, "Password Reset", "emails/auth/password-reset", vars);
    }

    /**
     * Internal method for sending password changed notification.
     * Used by both public overloads.
     */
    private Mono<Void> sendPasswordChangedNotificationInternal(
            String email,
            String fullName,
            String ipAddress,
            Instant changedAt,
            boolean forced) {

        String changeTypeLabel = forced ? "Admin-initiated" : "User-initiated";
        String changeTypeVerb = forced ? "administratively reset" : "changed";

        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", fullName != null ? fullName : email.split("@")[0]);
        variables.put("changeType", changeTypeVerb);
        variables.put("changeTypeLabel", changeTypeLabel);
        variables.put("ipAddress", ipAddress != null ? ipAddress : "Unknown");
        variables.put("changedAt", changedAt);
        variables.put("securityUrl", baseUrl + "/profile/security");

        String subject = "Password Changed – Security Alert";
        return sendTemplatedEmail(email, subject, "emails/auth/password-changed", variables);
    }

    /**
     * Main public method – used when fullName is not available.
     */
    @Override
    public Mono<Void> sendPasswordChangedNotification(
            String email,
            String ipAddress,
            Instant changedAt,
            boolean forced) {
        return sendPasswordChangedNotificationInternal(email, null, ipAddress, changedAt, forced);
    }

    /**
     * Overloaded method – used when fullName is available (e.g., from user object).
     */
    @Override
    public Mono<Void> sendPasswordChangedNotification(String email, String fullName, Instant changedAt) {
        return sendPasswordChangedNotificationInternal(email, fullName, "N/A", changedAt, false);
    }

    /**
     * Send password expiry warning
     */

    @Override
    public Mono<Void> sendPasswordExpiryWarning(
            String email,
            int daysRemaining,
            String language) {

        Instant now = clock.instant();

        // Prepare template variables
        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback
        variables.put("daysRemaining", daysRemaining);
        variables.put("currentDate", now);
        variables.put("changePasswordUrl", baseUrl + "/profile/security"); // adjust to your frontend route

        String subject = "Password expiry warning – Security Al";
        return sendTemplatedEmail(
                email,
                subject,
                "emails/auth/password-expiry-warning",
                variables

        );
    }

    /**
     * Send password expired notification
     */

    @Override
    public Mono<Void> sendPasswordExpiredNotification(
            String email,
            long daysExpired,
            String language) {

        Instant now = clock.instant();

        String subject = "password expired - Security Al";



        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback
        variables.put("daysExpired", daysExpired);
        variables.put("currentDate", now);
        variables.put("resetPasswordUrl", baseUrl + "/auth/forgot-password"); // adjust to your frontend route

        return sendTemplatedEmail(
                email,
                subject,
                "emails/auth/password-expired",
                variables

        );
    }

    /* =========================
       Account Security Emails
       ========================= */

    /**
     * Send account locked notification
     */

    @Override
    public Mono<Void> sendAccountLockedNotification(
            String email,
            Instant lockedAt,
            String reason,
            String ipAddress) {

        Instant now = clock.instant();

        String subject = "Account Locked – Security Alert";

        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback
        variables.put("lockedAt", lockedAt);
        variables.put("reason", reason != null ? reason : "Unspecified");
        variables.put("ipAddress", ipAddress != null ? ipAddress : "Unknown");
        variables.put("currentDate", now);
        variables.put("supportUrl", baseUrl + "/support"); // adjust to your support page

        return sendTemplatedEmail(
                email,
                subject,
                "emails/auth/account-locked",
                variables
        );
    }

    /* =========================
       Approval Workflow Emails
       ========================= */

    /**
     * Send user approved notification
     */
    // EmailServiceInstance.java

    @Override
    public void sendUserApprovedNotification(
            String email,
            String approvedBy,
            Instant approvedAt) {

        String subject = "Account Approved – Welcome!";

        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback
        variables.put("approvedBy", approvedBy != null ? approvedBy : "Administrator");
        variables.put("approvedAt", approvedAt);
        variables.put("loginUrl", baseUrl + "/login");

        sendTemplatedEmail(
                email,
                subject,
                "emails/auth/user-approved",
                variables
        );
    }

    /**
     * Send user rejected notification
     */

    @Override
    public void sendUserRejectedNotification(
            String email,
            String reason,
            Instant rejectedAt) {

        String subject = "Account Registration Decision";

        Map<String, Object> variables = new HashMap<>();
        variables.put("fullName", email.split("@")[0]); // fallback
        variables.put("reason", reason != null ? reason : "No specific reason provided");
        variables.put("rejectedAt", rejectedAt);
        variables.put("supportUrl", baseUrl + "/support");

        sendTemplatedEmail(
                email,
                subject,
                "emails/auth/user-rejected",
                variables
        );
    }
}