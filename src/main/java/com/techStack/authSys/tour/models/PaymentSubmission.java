package com.techStack.authSys.tour.models;


import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "payment_submissions",
        indexes = {
                @Index(name = "idx_payment_submission_quote", columnList = "quote_id"),
                @Index(name = "idx_payment_submission_status", columnList = "status")
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentSubmission extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "quote_id", nullable = false)
    private EnquiryQuote quote;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private PaymentChannel channel; // MPESA, BANK_TRANSFER

    @Column(name = "reference_code", nullable = false, length = 100)
    private String referenceCode;

    @Column(name = "amount_paid", nullable = false, precision = 12, scale = 2)
    private BigDecimal amountPaid;

    @Column(name = "payer_name", length = 150)
    private String payerName; // name the payment shows under, if different from customer name

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private PaymentSubmissionStatus status = PaymentSubmissionStatus.PENDING_VERIFICATION;

    @Column(name = "verified_by", length = 128)
    private String verifiedBy;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "rejection_reason", length = 500)
    private String rejectionReason;

    @Column(name = "related_booking_id")
    private UUID relatedBookingId;

    @Column(name = "related_booking_reference", length = 20)
    private String relatedBookingReference;
}
