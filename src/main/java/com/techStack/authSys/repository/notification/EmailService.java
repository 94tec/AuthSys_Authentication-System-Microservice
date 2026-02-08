package com.techStack.authSys.repository.notification;


import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Email Service Interface
 *
 * Defines all email sending operations.
 * Implementations should use Clock for timestamp tracking.
 */
public interface EmailService {

    /* Core Email Sending */
    Mono<Void> sendEmail(String email, String subject, String message);

    /* Verification Emails */
    Mono<Void> sendVerificationEmail(String email, String verificationToken);
    void sendEmailVerificationConfirmation(String email, Instant verifiedAt);

    /* Registration & Welcome */
    Mono<Void> sendWelcomeEmail(String email, String ipAddress);

    /* Authentication Events */
    Mono<Void> sendFirstLoginNotification(String email, String ipAddress, Instant loginTime);

    /* Password Management */
    Mono<Void> sendPasswordResetEmail(String email, String resetToken);
    Mono<Void> sendPasswordResetEmailToTheUser(String email, String tempPassword);
    Mono<Void> sendPasswordChangedNotification(String email, String ipAddress,
                                               Instant changedAt, boolean forced);
    Mono<Void> sendPasswordExpiryWarning(String email, int daysRemaining, String language);
    Mono<Void> sendPasswordExpiredNotification(String email, long daysExpired, String language);

    /* Account Security */
    Mono<Void> sendAccountLockedNotification(String userId, Instant eventTime, String reason, String ipAddresst);

    /* Approval Workflow */
    Mono<Void> sendUserApprovedNotification(String email, String approvedBy, Instant approvedAt);
    Mono<Void> sendUserRejectedNotification(String email, String reason, Instant rejectedAt);

}
