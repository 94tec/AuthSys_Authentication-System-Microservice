package com.techStack.authSys.notification.service;

import com.techStack.authSys.identity.models.ApprovalLevel;
import com.techStack.authSys.identity.models.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Admin Notification Service — approval workflow emails.
 * Renders Thymeleaf templates via EmailServiceInstance (delivered through Brevo).
 * Notifications are non-critical: failures are logged, never propagated.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AdminNotificationService {

    private static final DateTimeFormatter DISPLAY_FORMAT =
            DateTimeFormatter.ofPattern("MMMM dd, yyyy 'at' HH:mm z")
                    .withZone(ZoneId.of("Africa/Nairobi"));

    private final EmailServiceInstance emailService;
    private final Clock clock;

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

    /* ========================= Notifications ========================= */

    /** One email per admin recipient (addresses are not exposed to each other). */
    public Mono<Void> notifyAdminsForApproval(User user, ApprovalLevel approvalLevel) {
        Instant now = clock.instant();
        List<String> recipients = toRecipients(getRecipientsForApprovalLevel(approvalLevel));

        return Flux.fromIterable(recipients)
                .flatMap(to -> send(
                        to,
                        "🔔 New User Registration Requires Approval",
                        "emails/admin/approval-request",
                        approvalRequestVars(user, approvalLevel, now),
                        "approval request for " + user.getEmail() + " to " + to))
                .then();
    }

    /** Reuses emails/auth/user-approved (same variables as EmailServiceInstance). */
    public Mono<Void> notifyUserApproved(User user) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", user.getFirstName());
        vars.put("approvedBy", "Administrator");
        vars.put("approvedAt", clock.instant());
        vars.put("loginUrl", appUrl + "/login");

        return send(user.getEmail(), "Account Approved – Welcome!",
                "emails/auth/user-approved", vars,
                "approval confirmation to " + user.getEmail());
    }

    public Mono<Void> notifyUserRestored(User user) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", user.getFirstName());
        vars.put("email", user.getEmail());
        vars.put("restoredAt", DISPLAY_FORMAT.format(clock.instant()));
        vars.put("supportEmail", supportEmail);
        vars.put("appName", appName);

        return send(user.getEmail(), "Your Account Has Been Restored",
                "emails/auth/account-restored", vars,
                "restore confirmation to " + user.getEmail());
    }

    /** Reuses emails/auth/user-rejected (same variables as EmailServiceInstance). */
    public Mono<Void> notifyUserRejected(User user, String reason) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", user.getFirstName());
        vars.put("reason", reason != null ? reason : "No specific reason provided");
        vars.put("rejectedAt", clock.instant());
        vars.put("supportUrl", appUrl + "/support");

        return send(user.getEmail(), "Account Registration Decision",
                "emails/auth/user-rejected", vars,
                "rejection notice to " + user.getEmail());
    }

    /* ========================= Helpers ========================= */

    private Map<String, Object> approvalRequestVars(User user, ApprovalLevel level, Instant now) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("userEmail", user.getEmail());
        vars.put("userName", user.getFirstName() + " " + user.getLastName());
        vars.put("roles", String.valueOf(user.getRoles()));
        vars.put("approvalLevel", level.getDisplayName());
        vars.put("registeredAt", user.getCreatedAt() != null
                ? DISPLAY_FORMAT.format(user.getCreatedAt()) : "-");
        vars.put("reviewUrl", appUrl + "/admin/users/pending");
        vars.put("sentAt", DISPLAY_FORMAT.format(now));
        vars.put("appName", appName);
        return vars;
    }

    private Mono<Void> send(String to, String subject, String template,
                            Map<String, Object> vars, String label) {
        return emailService.sendTemplatedEmail(to, subject, template, vars)
                .doOnSuccess(v -> log.info("📧 Sent {}", label))
                .onErrorResume(e -> {
                    log.error("⚠️ Failed to send {}: {}", label, e.getMessage());
                    return Mono.empty(); // non-critical
                });
    }

    private List<String> toRecipients(String csv) {
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .distinct()
                .toList();
    }

    private String getRecipientsForApprovalLevel(ApprovalLevel level) {
        return switch (level) {
            case PENDING_L2 -> adminEmail + "," + superAdminEmail;
            case PENDING_L1 -> managerEmail + "," + adminEmail + "," + superAdminEmail;
            case NOT_REQUIRED, APPROVED_L1, APPROVED, REJECTED -> adminEmail;
        };
    }
}