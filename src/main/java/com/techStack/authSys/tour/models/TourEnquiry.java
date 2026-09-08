package com.techStack.authSys.tour.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(
        name = "tour_enquiries",
        indexes = {
                @Index(name = "idx_enquiry_tour",        columnList = "tour_id"),
                @Index(name = "idx_enquiry_user",        columnList = "user_id"),
                @Index(name = "idx_enquiry_status",      columnList = "status"),
                @Index(name = "idx_enquiry_assigned_to", columnList = "assigned_to"),
                @Index(name = "idx_enquiry_status_assigned", columnList = "status, assigned_to"),
                @Index(name = "idx_enquiry_travel_end", columnList = "travel_end_date"),
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TourEnquiry extends BaseEntity {

    // id, createdDate, lastModifiedDate, createdBy, lastModifiedBy,
    // isDeleted, version → all inherited from BaseEntity. Do NOT redeclare id.

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tour_id", nullable = false)
    private Tour tour;

    /** Firebase UID of the submitter — matches CustomUserDetails.getUserId(), NOT a Postgres UUID. */
    @Column(name = "user_id", nullable = false, updatable = false, length = 128)
    private String userId;

    @Column(name = "full_name", nullable = false, length = 120)
    private String fullName;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(length = 32)
    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(name = "preferred_contact", length = 20)
    private PreferredContact preferredContact;

    @Column(name = "preferred_date")
    private LocalDate preferredDate;

    @Builder.Default
    @Column(name = "flexible_dates", nullable = false)
    private Boolean flexibleDates = false;

    @Column(name = "group_size_adults")
    private Integer groupSizeAdults;

    @Column(name = "group_size_children")
    private Integer groupSizeChildren;

    @Column(name = "budget_range", length = 100)
    private String budgetRange;

    @Column(length = 2000)
    private String requirements;

    @Column(length = 150)
    private String source;

    @Builder.Default
    @Column(nullable = false)
    private Boolean consent = true;

    @Column(length = 2000)
    private String notes;

    @Column(name = "assigned_to")
    private String assignedTo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private TourEnquiryStatus status = TourEnquiryStatus.NEW;

    // ── Lifecycle tracking ───────────────────────────────────
    @Column(name = "booking_reference", length = 60)
    private String bookingReference;

    @Column(name = "travel_start_date")
    private LocalDate travelStartDate;

    @Column(name = "travel_end_date")
    private LocalDate travelEndDate;

    @Column(name = "appreciation_sent_at")
    private Instant appreciationSentAt;

    @Column(name = "first_contacted_at")
    private Instant firstContactedAt;
}