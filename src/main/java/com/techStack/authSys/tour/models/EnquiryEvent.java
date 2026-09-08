package com.techStack.authSys.tour.models;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

/**
 * Maps onto the pre-existing enquiry_events table. Deliberately does NOT
 * extend BaseEntity — this table has no is_deleted/version/created_by
 * columns, it's an append-only event ledger, not a managed entity.
 */
@Entity
@Table(name = "enquiry_events")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EnquiryEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "enquiry_id", nullable = false)
    private TourEnquiry enquiry;

    @Column(name = "actor_id")
    private String actorId;

    @Enumerated(EnumType.STRING)
    @Column(name = "actor_type", nullable = false, length = 20)
    private ActorType actorType;

    /** Maps to the existing event_type column — kept your name, not "action". */
    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private ActivityAction eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "from_status", length = 20)
    private TourEnquiryStatus fromStatus;

    @Enumerated(EnumType.STRING)
    @Column(name = "to_status", length = 20)
    private TourEnquiryStatus toStatus;

    /** Maps to the existing details column — kept your name, not "note". */
    @Column(name = "details", length = 2000)
    private String details;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private Instant createdAt;
}