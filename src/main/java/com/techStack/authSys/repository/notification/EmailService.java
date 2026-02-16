package com.techStack.authSys.repository.notification;

import reactor.core.publisher.Mono;

import java.time.Instant;

/**
 * Email Service Interface
 *
 * Defines all email sending operations.
 * Implementations should use Clock for timestamp tracking.
 *
 * ⭐ ENHANCED: Added missing methods for FirstTimeLoginSetupService
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

    // ⭐ NEW: Overloaded method for simpler signature (used by FirstTimeLoginSetupService)
    Mono<Void> sendPasswordChangedNotification(String email, String fullName, Instant changedAt);

    Mono<Void> sendPasswordExpiryWarning(String email, int daysRemaining, String language);
    Mono<Void> sendPasswordExpiredNotification(String email, long daysExpired, String language);

    /* Account Security */
    Mono<Void> sendAccountLockedNotification(String userId, Instant eventTime, String reason, String ipAddress);

    /* Approval Workflow */
    Mono<Void> sendUserApprovedNotification(String email, String approvedBy, Instant approvedAt);
    Mono<Void> sendUserRejectedNotification(String email, String reason, Instant rejectedAt);

    /* ⭐ NEW: OTP Notifications for FirstTimeLoginSetupService */

    /**
     * Send OTP notification email
     *
     * Used in Step 1 of FirstTimeLoginSetupService after OTP is sent via SMS
     *
     * @param email User's email address
     * @param fullName User's full name
     * @param purpose Purpose of OTP (e.g., "Complete your first-time setup with OTP")
     * @param sentAt Timestamp when OTP was sent
     * @return Mono<Void> completing when email sent
     */
    Mono<Void> sendOtpNotification(String email, String fullName, String purpose, Instant sentAt);
}