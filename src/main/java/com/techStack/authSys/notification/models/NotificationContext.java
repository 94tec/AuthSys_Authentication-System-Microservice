package com.techStack.authSys.notification.models;

import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;

/**
 * Carries all the data needed to render notification templates
 * for a specific event. Passed from NotificationService to each
 * channel service (email, SMS, WhatsApp).
 *
 * Built once per event in NotificationService.buildContext() and
 * reused across all channels — avoids repeated DB lookups.
 *
 * Template variables map directly to fields here:
 *   {{customerName}}  → customerName
 *   {{tourName}}      → tourName
 *   {{tourDate}}      → tourDate
 *   {{totalPrice}}    → totalPrice
 *   {{currency}}      → currency
 *   etc.
 */
@Getter
@Builder
public class NotificationContext {

    // ── Recipient ─────────────────────────────────────────────────────────────
    private final String customerId;
    private final String customerName;
    private final String customerEmail;
    private final String customerPhone;       // 2547XXXXXXXX or null

    // ── Opt-in flags (read from CustomerProfile) ──────────────────────────────
    private final boolean emailOptIn;         // always true for transactional
    private final boolean smsOptIn;
    private final boolean whatsAppOptIn;      // same flag as smsOptIn

    // ── Booking data (null for non-booking notifications) ─────────────────────
    private final UUID        bookingId;
    private final String      tourName;
    private final LocalDate   tourDate;
    private final Integer     travelerCount;
    private final BigDecimal  totalPrice;
    private final String      currency;
    private final String      cancellationReason;
    private final String      paymentReference;   // M-Pesa receipt number

    // ── Payment data (null for non-payment notifications) ─────────────────────
    private final UUID        paymentId;
    private final BigDecimal  paymentAmount;
    private final String      mpesaReceiptNumber;
    private final String      paymentFailureReason;

    // ── Account data (null for non-account notifications) ─────────────────────
    private final String      rejectionReason;
    private final String      passwordResetUrl;

    // ── Reference for NotificationLog ─────────────────────────────────────────
    private final String      referenceId;      // UUID as string
    private final String      referenceType;    // "BOOKING", "PAYMENT", "USER"
    private final UUID        correlationId;    // groups all channels for one event
}
