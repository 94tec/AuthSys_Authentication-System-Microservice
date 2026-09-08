package com.techStack.authSys.payment.models;

import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

/**
 * Payment record for a Damuchi Safaris booking.
 *
 * One Payment is created per payment attempt.
 * A booking may have multiple Payment rows if the first attempt fails
 * and the customer retries — only one SUCCESS payment should exist per booking.
 *
 * Created by PaymentService.initiateMpesaPayment() when the STK push is sent.
 * Updated by PaymentService.handleMpesaCallback() when Safaricom calls back.
 *
 * On status → SUCCESS:
 *   PaymentService calls BookingService.confirmBooking(bookingId, mpesaReceiptNumber)
 *   which transitions Booking.status → CONFIRMED and sets paymentReference.
 *
 * Columns:
 *   checkoutRequestId   — Safaricom's STK push request identifier
 *                         used to match the async callback to this Payment row.
 *   merchantRequestId   — Safaricom's merchant-side request ID (pair with above).
 *   mpesaReceiptNumber  — Safaricom transaction ID on SUCCESS (e.g. "QHT7AN6BA2").
 *                         Stored on Payment AND passed to Booking.confirm() as paymentReference.
 *   rawCallbackPayload  — full JSON from Safaricom callback, stored for audit/replay.
 *   phoneNumber         — the number STK push was sent to (for receipts).
 */
@Entity
@Table(
    name = "payments",
    indexes = {
        @Index(name = "idx_payment_booking",            columnList = "booking_id"),
        @Index(name = "idx_payment_status",             columnList = "status"),
        @Index(name = "idx_payment_checkout_request",   columnList = "checkout_request_id"),
        @Index(name = "idx_payment_mpesa_receipt",      columnList = "mpesa_receipt_number"),
        @Index(name = "idx_payment_customer",           columnList = "customer_id")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Payment extends BaseEntity {

    // ── Booking link ─────────────────────────────────────────────────────────

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "booking_id", nullable = false, updatable = false)
    private Booking booking;

    /**
     * Denormalised customer ID — allows payment queries without joining Booking.
     * Matches Booking.customerId (Firebase UID).
     */
    @NotBlank
    @Column(name = "customer_id", nullable = false, length = 128, updatable = false)
    private String customerId;

    // ── Amount ───────────────────────────────────────────────────────────────

    @NotNull
    @DecimalMin("1.00")
    @Column(name = "amount", nullable = false, precision = 12, scale = 2, updatable = false)
    private BigDecimal amount;

    @Column(name = "currency", length = 3, nullable = false, updatable = false)
    @Builder.Default
    private String currency = "KES";

    // ── Method & status ───────────────────────────────────────────────────────

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "method", nullable = false, length = 20, updatable = false)
    private PaymentMethod method;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private PaymentStatus status = PaymentStatus.PENDING;

    // ── M-Pesa Daraja fields ──────────────────────────────────────────────────

    /**
     * Phone number the STK push was sent to.
     * Format: 2547XXXXXXXX (no leading +).
     */
    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    /**
     * Safaricom STK push CheckoutRequestID.
     * Used as the key to match the async callback to this Payment row.
     * e.g. "ws_CO_191220191020363925"
     */
    @Column(name = "checkout_request_id", length = 100)
    private String checkoutRequestId;

    /**
     * Safaricom MerchantRequestID — paired with checkoutRequestId.
     * e.g. "29115-34620561-1"
     */
    @Column(name = "merchant_request_id", length = 100)
    private String merchantRequestId;

    /**
     * Safaricom transaction receipt number — only present on SUCCESS.
     * e.g. "QHT7AN6BA2"
     * Passed to BookingService.confirmBooking() as the paymentReference.
     */
    @Column(name = "mpesa_receipt_number", length = 50)
    private String mpesaReceiptNumber;

    /**
     * Safaricom result code from callback.
     * 0 = SUCCESS, anything else = failure.
     * Stored for debugging and customer service.
     */
    @Column(name = "result_code")
    private Integer resultCode;

    /**
     * Safaricom result description from callback.
     * e.g. "The service request is processed successfully."
     */
    @Column(name = "result_description", length = 300)
    private String resultDescription;

    /**
     * Full raw JSON of the Safaricom callback body.
     * Stored as TEXT for audit, replay, and debugging.
     */
    @Column(name = "raw_callback_payload", columnDefinition = "TEXT")
    private String rawCallbackPayload;

    // ── Timestamps ────────────────────────────────────────────────────────────

    /** When the STK push was initiated (set at creation). */
    @Column(name = "initiated_at", updatable = false)
    @Builder.Default
    private OffsetDateTime initiatedAt = OffsetDateTime.now();

    /** When the callback was received and processed. */
    @Column(name = "completed_at")
    private OffsetDateTime completedAt;

    // ── Domain methods ────────────────────────────────────────────────────────

    /**
     * Mark this payment as successful.
     * Called by PaymentService.handleMpesaCallback() on ResultCode == 0.
     */
    public void markSuccess(String mpesaReceiptNumber, String rawPayload) {
        this.status              = PaymentStatus.SUCCESS;
        this.mpesaReceiptNumber  = mpesaReceiptNumber;
        this.rawCallbackPayload  = rawPayload;
        this.resultCode          = 0;
        this.resultDescription   = "Payment successful";
        this.completedAt         = OffsetDateTime.now();
    }

    /**
     * Mark this payment as failed.
     * Called by PaymentService.handleMpesaCallback() on ResultCode != 0.
     */
    public void markFailed(int resultCode, String description, String rawPayload) {
        this.status             = PaymentStatus.FAILED;
        this.resultCode         = resultCode;
        this.resultDescription  = description;
        this.rawCallbackPayload = rawPayload;
        this.completedAt        = OffsetDateTime.now();
    }

    /**
     * Mark as cancelled — customer dismissed the STK push.
     * ResultCode 1032 = "Request cancelled by user".
     */
    public void markCancelled(String rawPayload) {
        this.status             = PaymentStatus.CANCELLED;
        this.resultCode         = 1032;
        this.resultDescription  = "Request cancelled by user";
        this.rawCallbackPayload = rawPayload;
        this.completedAt        = OffsetDateTime.now();
    }

    /**
     * Mark as refunded — called by PaymentService.processRefund().
     */
    public void markRefunded() {
        this.status = PaymentStatus.REFUNDED;
        this.completedAt = OffsetDateTime.now();
    }
}
