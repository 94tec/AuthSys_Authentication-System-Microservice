package com.techStack.authSys.notification.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Audit record for every notification attempt made by the system.
 *
 * One row per channel per notification event.
 * e.g. BOOKING_CONFIRMED for customer X creates:
 *   - row 1: channel=EMAIL,    status=SENT
 *   - row 2: channel=WHATSAPP, status=SENT
 *   - row 3: channel=SMS,      status=SKIPPED (smsOptIn=false)
 *
 * Used for:
 *   - Debugging delivery failures
 *   - Customer service ("did the confirmation email send?")
 *   - Admin notification dashboard
 *   - Retry logic (status=PENDING + attempts < maxRetries)
 *   - In-app notification bell (channel=IN_APP, status=SENT/DELIVERED)
 *
 * correlationId groups all channels for the same logical notification event,
 * e.g. all 3 rows above share the same correlationId UUID.
 */
@Entity
@Table(
    name = "notification_log",
    indexes = {
        @Index(name = "idx_notif_customer",       columnList = "customer_id"),
        @Index(name = "idx_notif_type",           columnList = "notification_type"),
        @Index(name = "idx_notif_status",         columnList = "status"),
        @Index(name = "idx_notif_channel",        columnList = "channel"),
        @Index(name = "idx_notif_correlation",    columnList = "correlation_id"),
        @Index(name = "idx_notif_reference",      columnList = "reference_id"),
        @Index(name = "idx_notif_created",        columnList = "created_date"),
        @Index(name = "idx_notif_pending_retry",  columnList = "status, attempts")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NotificationLog extends BaseEntity {

    // ── Recipient ─────────────────────────────────────────────────────────────

    /** Firebase UID of the recipient. */
    @NotBlank
    @Column(name = "customer_id", nullable = false, length = 128)
    private String customerId;

    /** Resolved at send time — stored for audit even if email changes later. */
    @Column(name = "recipient_email", length = 255)
    private String recipientEmail;

    /** Resolved at send time. Format: 2547XXXXXXXX. */
    @Column(name = "recipient_phone", length = 20)
    private String recipientPhone;

    @Column(name = "recipient_name", length = 200)
    private String recipientName;

    // ── Classification ────────────────────────────────────────────────────────

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "notification_type", nullable = false, length = 30)
    private NotificationType notificationType;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "channel", nullable = false, length = 15)
    private NotificationChannel channel;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 15)
    @Builder.Default
    private NotificationStatus status = NotificationStatus.PENDING;

    // ── Correlation ───────────────────────────────────────────────────────────

    /**
     * Groups all channel rows for the same logical notification event.
     * Generated once per event in NotificationService.send() and
     * passed to each channel dispatch call.
     */
    @Column(name = "correlation_id", nullable = false)
    private UUID correlationId;

    /**
     * ID of the entity that triggered this notification.
     * e.g. bookingId for BOOKING_CONFIRMED, paymentId for PAYMENT_RECEIVED.
     * Stored as VARCHAR to support different entity types without FK complexity.
     */
    @Column(name = "reference_id", length = 36)
    private String referenceId;

    /**
     * Entity type for the reference — e.g. "BOOKING", "PAYMENT", "USER".
     * Used with referenceId to reconstruct context without JOINs.
     */
    @Column(name = "reference_type", length = 20)
    private String referenceType;

    // ── Content ───────────────────────────────────────────────────────────────

    /** Subject line — populated for EMAIL channel only. */
    @Column(name = "subject", length = 200)
    private String subject;

    /** Resolved message body sent to the provider. Stored for audit/replay. */
    @Column(name = "body", columnDefinition = "TEXT")
    private String body;

    // ── Delivery tracking ─────────────────────────────────────────────────────

    /**
     * Provider message ID returned on success.
     * Brevo: message-id header.
     * Africa's Talking: messageId from response.
     * Used for delivery status webhooks.
     */
    @Column(name = "provider_message_id", length = 200)
    private String providerMessageId;

    /** Number of send attempts (including first attempt). */
    @Column(name = "attempts", nullable = false)
    @Builder.Default
    private int attempts = 0;

    /** When the last send attempt was made. */
    @Column(name = "last_attempt_at")
    private OffsetDateTime lastAttemptAt;

    /** When the provider confirmed delivery (for channels that support callbacks). */
    @Column(name = "delivered_at")
    private OffsetDateTime deliveredAt;

    /**
     * Error message from the provider on failure.
     * Stored for debugging — never exposed to customers.
     */
    @Column(name = "error_message", length = 500)
    private String errorMessage;

    // ── Domain methods ────────────────────────────────────────────────────────

    public void markSent(String providerMessageId) {
        this.status            = NotificationStatus.SENT;
        this.providerMessageId = providerMessageId;
        this.lastAttemptAt     = OffsetDateTime.now();
        this.attempts++;
        this.errorMessage      = null;
    }

    public void markDelivered() {
        this.status      = NotificationStatus.DELIVERED;
        this.deliveredAt = OffsetDateTime.now();
    }

    public void markFailed(String errorMessage) {
        this.status        = NotificationStatus.FAILED;
        this.errorMessage  = errorMessage;
        this.lastAttemptAt = OffsetDateTime.now();
        this.attempts++;
    }

    public void markSkipped(String reason) {
        this.status       = NotificationStatus.SKIPPED;
        this.errorMessage = reason;
    }

    public boolean isRetryable(int maxRetries) {
        return status == NotificationStatus.FAILED
            || status == NotificationStatus.PENDING
            && attempts < maxRetries;
    }
}
