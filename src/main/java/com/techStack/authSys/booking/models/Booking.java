package com.techStack.authSys.booking.models;

import com.techStack.authSys.common.models.BaseEntity;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourAvailability;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(
        name = "bookings",
        indexes = {
                @Index(name = "idx_bookings_customer_id",      columnList = "customer_id"),
                @Index(name = "idx_bookings_tour_id",          columnList = "tour_id"),
                @Index(name = "idx_bookings_availability_id",  columnList = "availability_id"),
                @Index(name = "idx_bookings_status",           columnList = "status"),
                @Index(name = "idx_bookings_tour_date",        columnList = "tour_date")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Booking extends BaseEntity {

    // ── Customer ─────────────────────────────────────────────────────────────

    /**
     * Firebase UID — ties this booking to a User in authSys.
     * Stored as plain string (not a FK) because User lives in Firestore,
     * not in the same PostgreSQL database as bookings.
     */
    @NotBlank
    @Column(name = "customer_id", nullable = false, length = 128)
    private String customerId;

    @NotBlank
    @Email
    @Column(name = "customer_email", nullable = false, length = 255)
    private String customerEmail;

    @NotBlank
    @Column(name = "customer_name", nullable = false, length = 255)
    private String customerName;

    // ── Tour reference ────────────────────────────────────────────────────────

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "tour_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_booking_tour")
    )
    private Tour tour;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "availability_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_booking_availability")
    )
    private TourAvailability availability;

    /**
     * Denormalized from availability.date — allows date-range queries
     * and reporting without joining tour_availability every time.
     */
    @NotNull
    @Column(name = "tour_date", nullable = false)
    private LocalDate tourDate;

    /**
     * Denormalized from tour.name — preserves the display name even if
     * the tour is later renamed, soft-deleted, or archived.
     */
    @NotBlank
    @Column(name = "tour_name", nullable = false, length = 150)
    private String tourName;

    // ── Party ──────────────────────────────────────────────────────────────────

    @NotNull
    @Min(1)
    @Column(name = "traveler_count", nullable = false)
    private Integer travelerCount;

    @OneToMany(
            mappedBy = "booking",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    @Builder.Default
    private List<BookingTraveler> travelers = new ArrayList<>();

    // ── Pricing snapshot ───────────────────────────────────────────────────────

    @NotNull
    @DecimalMin("0.00")
    @Column(name = "price_per_traveler", nullable = false, precision = 10, scale = 2)
    private BigDecimal pricePerTraveler;

    @NotNull
    @DecimalMin("0.00")
    @Column(name = "total_price", nullable = false, precision = 10, scale = 2)
    private BigDecimal totalPrice;

    @NotBlank
    @Column(name = "currency", nullable = false, length = 3)
    @Builder.Default
    private String currency = "KES";

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    @Builder.Default
    private BookingStatus status = BookingStatus.PENDING_PAYMENT;

    // ── Payment ────────────────────────────────────────────────────────────────

    @Column(name = "payment_reference", length = 255)
    private String paymentReference;

    @Column(name = "paid_at")
    private Instant paidAt;

    // ── Cancellation / refund ──────────────────────────────────────────────────

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Size(max = 500)
    @Column(name = "cancellation_reason", length = 500)
    private String cancellationReason;

    @Column(name = "refund_reference", length = 255)
    private String refundReference;

    @Column(name = "refunded_at")
    private Instant refundedAt;

    // ── Customer notes ─────────────────────────────────────────────────────────

    @Size(max = 1000)
    @Column(name = "special_requests", length = 1000)
    private String specialRequests;

    // ── Convenience methods ────────────────────────────────────────────────────

    /**
     * Adds a traveler and sets the back-reference.
     * Always use this instead of getTravelers().add() directly.
     */
    public void addTraveler(BookingTraveler traveler) {
        travelers.add(traveler);
        traveler.setBooking(this);
    }

    /**
     * Removes a traveler and clears the back-reference.
     */
    public void removeTraveler(BookingTraveler traveler) {
        travelers.remove(traveler);
        traveler.setBooking(null);
    }

    /**
     * Confirms this booking after payment is verified.
     * Sets status → CONFIRMED, records payment reference and paid timestamp.
     */
    public void confirm(String paymentReference) {
        if (this.status != BookingStatus.PENDING_PAYMENT) {
            throw new IllegalStateException(
                    "Only PENDING_PAYMENT bookings can be confirmed. Current: "
                            + this.status.name());
        }
        this.status = BookingStatus.CONFIRMED;
        this.paymentReference = paymentReference;
        this.paidAt = Instant.now();
    }

    /**
     * Cancels this booking.
     * Sets status → CANCELLED, records reason and timestamp, soft-deletes.
     * Slot release is handled by BookingService before calling this method.
     */
    public void cancel(String reason) {
        if (!status.isCancellable()) {
            throw new IllegalStateException(
                    "Cannot cancel a booking in status: " + status.name());
        }
        this.status = BookingStatus.CANCELLED;
        this.cancelledAt = Instant.now();
        this.cancellationReason = reason;
        this.setDeleted(true);
    }

    /**
     * Marks this booking as refunded after payment is returned.
     * Must be CANCELLED first.
     */
    public void refund(String refundReference) {
        if (this.status != BookingStatus.CANCELLED) {
            throw new IllegalStateException(
                    "Only CANCELLED bookings can be refunded. Current: "
                            + this.status.name());
        }
        this.status = BookingStatus.REFUNDED;
        this.refundReference = refundReference;
        this.refundedAt = Instant.now();
    }

    /**
     * Marks this booking as COMPLETED after the tour has run.
     * Must be CONFIRMED first.
     */
    public void complete() {
        if (this.status != BookingStatus.CONFIRMED) {
            throw new IllegalStateException(
                    "Only CONFIRMED bookings can be completed. Current: "
                            + this.status.name());
        }
        this.status = BookingStatus.COMPLETED;
    }
}