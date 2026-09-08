package com.techStack.authSys.notification.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * All notification types in the Damuchi Safaris system.
 *
 * Each type maps to:
 *   - a specific trigger event (booking lifecycle, payment, reminder)
 *   - a template set in resources/templates/{channel}/{type}.txt
 *   - a set of allowed channels (see NotificationService.getChannelsFor())
 *
 * Booking lifecycle:
 *   BOOKING_CREATED      → customer books, awaiting payment
 *   BOOKING_CONFIRMED    → payment received, booking active
 *   BOOKING_CANCELLED    → booking cancelled (customer or staff)
 *   BOOKING_COMPLETED    → enquire-button.tsx ran successfully
 *   BOOKING_REMINDER     → 24h before enquire-button.tsx date (scheduled job)
 *
 * Payment:
 *   PAYMENT_RECEIVED     → M-Pesa SUCCESS callback processed
 *   PAYMENT_FAILED       → STK push failed or timed out
 *   PAYMENT_REFUNDED     → refund processed by ADMIN
 *
 * Account:
 *   ACCOUNT_APPROVED     → admin approved a pending registration
 *   ACCOUNT_REJECTED     → admin rejected a registration
 *   WELCOME              → first login after account approval
 *   PASSWORD_RESET       → password reset link email
 *
 * Marketing (respects emailMarketingOptIn / smsOptIn):
 *   PROMOTIONAL          → new enquire-button.tsx packages, seasonal offers
 *   REVIEW_REQUEST       → ask for review 3 days after COMPLETED
 */
@Getter
@RequiredArgsConstructor
public enum NotificationType {

    // Booking lifecycle
    BOOKING_CREATED(   "Booking Received",        false),
    BOOKING_CONFIRMED( "Booking Confirmed",        false),
    BOOKING_CANCELLED( "Booking Cancelled",        false),
    BOOKING_COMPLETED( "Tour Completed",           false),
    BOOKING_REMINDER(  "Tour Reminder",            false),

    // Payment
    PAYMENT_RECEIVED(  "Payment Received",         false),
    PAYMENT_FAILED(    "Payment Failed",           false),
    PAYMENT_REFUNDED(  "Refund Processed",         false),

    // Account
    ACCOUNT_APPROVED(  "Account Approved",         false),
    ACCOUNT_REJECTED(  "Account Rejected",         false),
    WELCOME(           "Welcome to Damuchi Safaris", false),
    PASSWORD_RESET(    "Password Reset",           false),

    // Marketing — only sent when customer has opted in
    PROMOTIONAL(       "Special Offer",            true),
    REVIEW_REQUEST(    "Share Your Experience",    true);

    private final String displayName;

    /**
     * If true, only sent to customers who opted in to marketing communications.
     * Transactional notifications (booking, payment, account) are always sent.
     */
    private final boolean marketingOnly;
}
