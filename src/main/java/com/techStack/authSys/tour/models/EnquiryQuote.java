package com.techStack.authSys.tour.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;

@Entity
@Table(
        name = "enquiry_quotes",
        indexes = {
                @Index(name = "idx_quote_enquiry", columnList = "enquiry_id"),
                @Index(name = "idx_quote_status_valid", columnList = "status, valid_until")
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EnquiryQuote extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "enquiry_id", nullable = false)
    private TourEnquiry enquiry;

    @Column(name = "adult_count", nullable = false)
    @Builder.Default
    private Integer adultCount = 0;

    @Column(name = "child_count", nullable = false)
    @Builder.Default
    private Integer childCount = 0;

    @Column(name = "price_per_adult", nullable = false, precision = 12, scale = 2)
    private BigDecimal pricePerAdult;

    @Column(name = "price_per_child", precision = 12, scale = 2)
    private BigDecimal pricePerChild;

    @Column(name = "total_price", nullable = false, precision = 12, scale = 2)
    private BigDecimal totalPrice;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 3)
    private TourCurrency currency;

    @Column(name = "valid_until", nullable = false)
    private LocalDate validUntil;

    @Column(length = 2000)
    private String inclusionsNote;

    @Column(length = 1000)
    private String internalNote;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private QuoteStatus status = QuoteStatus.DRAFT;

    @Column(name = "sent_at")
    private Instant sentAt;

    @Column(name = "responded_at")
    private Instant respondedAt;
}