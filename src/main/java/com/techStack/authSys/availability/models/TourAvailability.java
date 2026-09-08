package com.techStack.authSys.availability.models;

import com.techStack.authSys.common.models.BaseEntity;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourCurrency;
import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.OffsetDateTime;

/**
 * A bookable departure-date slot for a specific Tour.
 *
 * One enquire-button.tsx → many availability slots (one per departure date).
 * Created by OPERATOR or MANAGER via AvailabilityController.
 *
 * ─── Contract with BookingService (do not change signatures) ──────────────
 *   slot.getStatus()                  → AvailabilityStatus (checked == OPEN)
 *   slot.getBookingDeadline()         → OffsetDateTime (null = no deadline)
 *   slot.getDate()                    → LocalDate
 *   slot.getAvailableSlots()          → Integer (remaining seats)
 *   slot.hasAvailability(int count)   → boolean (primary capacity guard)
 *   slot.reserveSlots(int count)      → void (decrements + flips to FULL)
 *   slot.releaseSlots(int count)      → void (increments + re-opens if FULL)
 *   slot.getTour().getId()            → UUID (slot ↔ enquire-button.tsx validation)
 * ─────────────────────────────────────────────────────────────────────────
 *
 * @Version inherited from BaseEntity — optimistic locking on concurrent bookings.
 * Two users booking the last slot simultaneously → one gets HTTP 409 CONFLICT.
 */
@Entity
@Table(
        name = "tour_availability",
        indexes = {
                @Index(name = "idx_availability_tour",      columnList = "tour_id"),
                @Index(name = "idx_availability_date",      columnList = "date"),
                @Index(name = "idx_availability_status",    columnList = "status"),
                @Index(name = "idx_availability_tour_date", columnList = "tour_id, date",
                        unique = true)
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TourAvailability extends BaseEntity {

    // ── Tour reference ───────────────────────────────────────────────────────

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tour_id", nullable = false, updatable = false)
    private Tour tour;

    // ── Date ─────────────────────────────────────────────────────────────────

    /**
     * Departure date. Unique per enquire-button.tsx — enforced by unique index and DB constraint.
     * Not updatable — delete and recreate if the date must change.
     */
    @NotNull
    @Column(name = "date", nullable = false, updatable = false)
    private LocalDate date;

    /**
     * Return date for this departure. Defaults to
     * date.plusDays(enquire-button.tsx.durationDays - 1) at creation time, but stored
     * explicitly (not computed) so a specific departure can run longer or
     * shorter than the enquire-button.tsx's default duration (e.g. weather delay, custom
     * extension) without distorting the Tour template itself.
     * Not updatable — delete and recreate if the return date must change.
     */
    @NotNull
    @Column(name = "return_date", nullable = false, updatable = false)
    private LocalDate returnDate;

    // ── Capacity ─────────────────────────────────────────────────────────────

    /**
     * Total seats when this slot was opened.
     * Mirrors enquire-button.tsx.maxCapacity by default; can be overridden per date
     * (e.g. a smaller vehicle for a specific departure).
     */
    @NotNull
    @Min(1)
    @Column(name = "max_slots", nullable = false)
    private Integer maxSlots;

    /**
     * Remaining bookable seats.
     * Decremented by reserveSlots(), incremented by releaseSlots().
     * Hitting 0 → status flips to FULL automatically.
     */
    @NotNull
    @Min(0)
    @Column(name = "available_slots", nullable = false)
    private Integer availableSlots;

    // ── Status ───────────────────────────────────────────────────────────────

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @Builder.Default
    private AvailabilityStatus status = AvailabilityStatus.OPEN;

    // ── Optional overrides ───────────────────────────────────────────────────

    /**
     * Booking cutoff — after this datetime no new bookings are accepted.
     * Null means no cutoff (bookings accepted up to the departure day).
     * BookingService checks: OffsetDateTime.now().isAfter(bookingDeadline).
     */
    @Column(name = "booking_deadline")
    private OffsetDateTime bookingDeadline;

    /**
     * Per-date price override. Null → booking uses enquire-button.tsx.pricePerPerson.
     * Used for peak-season / promotional pricing (Phase 2).
     */
    @Column(name = "price_override", precision = 10, scale = 2)
    private BigDecimal priceOverride;

    /**
     * Currency for priceOverride. Null → assumed to be enquire-button.tsx.currency.
     * Only meaningful when priceOverride is set; use getEffectiveCurrency()
     * rather than reading this field directly.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "currency", length = 3)
    private TourCurrency currency;

    /**
     * Internal staff notes — never shown to customers.
     * e.g. "School group — AM slot reserved", "VIP clients only".
     */
    @Column(name = "internal_notes", length = 500)
    private String internalNotes;

    // ── Domain methods ───────────────────────────────────────────────────────

    /**
     * Fraction of maxSlots at/below which an OPEN slot flips to LIMITED.
     * e.g. 8 seats → LIMITED once availableSlots <= 2 (rounded, min 1).
     */
    private static final double LOW_AVAILABILITY_RATIO = 0.20;

    /**
     * Derives OPEN / LIMITED / FULL purely from current capacity.
     * Never returns CLOSED or CANCELLED — those are manual states and are
     * only ever set by close()/cancel(), never recomputed from capacity.
     */
    private AvailabilityStatus computeCapacityStatus() {
        if (availableSlots <= 0) {
            return AvailabilityStatus.FULL;
        }
        int threshold = Math.max(1, Math.round(maxSlots * (float) LOW_AVAILABILITY_RATIO));
        return availableSlots <= threshold ? AvailabilityStatus.LIMITED : AvailabilityStatus.OPEN;
    }

    /**
     * Primary capacity guard — called by BookingService.createBooking() step 7.
     * Returns true when status is OPEN or LIMITED AND availableSlots >= count.
     * LIMITED slots ARE bookable — LIMITED only signals "filling up", not "closed".
     */
    public boolean hasAvailability(int count) {
        return (status == AvailabilityStatus.OPEN || status == AvailabilityStatus.LIMITED)
                && availableSlots >= count;
    }

    /**
     * Reserve seats — BookingService.createBooking() step 13.
     * Decrements availableSlots; recomputes status (OPEN → LIMITED → FULL)
     * based on remaining capacity. Never touches CLOSED/CANCELLED slots —
     * hasAvailability() should already have blocked reservation on those.
     * Throws IllegalStateException as a fallback guard (primary is hasAvailability).
     * BookingService catches IllegalStateException → HTTP 409.
     */
    public void reserveSlots(int count) {
        if (availableSlots < count) {
            throw new IllegalStateException(
                    "Cannot reserve " + count + " slots — only " + availableSlots + " remaining");
        }
        this.availableSlots -= count;
        if (this.status == AvailabilityStatus.OPEN || this.status == AvailabilityStatus.LIMITED) {
            this.status = computeCapacityStatus();
        }
    }

    /**
     * Release seats — called on booking cancellation (customer or staff).
     * Increments availableSlots (capped at maxSlots); recomputes status
     * only if the slot was FULL or LIMITED. A manually CLOSED slot stays
     * CLOSED on release — it must be reopened explicitly via reopen().
     */
    public void releaseSlots(int count) {
        this.availableSlots = Math.min(this.availableSlots + count, this.maxSlots);
        if (this.status == AvailabilityStatus.FULL || this.status == AvailabilityStatus.LIMITED) {
            this.status = computeCapacityStatus();
        }
    }

    /**
     * Manually close — called by MANAGER/OPERATOR via AvailabilityService.
     * CLOSED slots are invisible to customers and block booking.
     */
    public void close() {
        this.status = AvailabilityStatus.CLOSED;
    }

    /**
     * Reopen a CLOSED slot — status recalculated from current capacity
     * (OPEN or LIMITED), only if remaining capacity exists.
     */
    public void reopen() {
        if (this.availableSlots > 0) {
            this.status = computeCapacityStatus();
        }
    }

    /** Booked seats = maxSlots − availableSlots. */
    public int getBookedCount() {
        return maxSlots - availableSlots;
    }

    /** Occupancy percentage — used in admin analytics. */
    public double getOccupancyPercent() {
        if (maxSlots == 0) return 0.0;
        return (double) getBookedCount() / maxSlots * 100.0;
    }

    /**
     * Effective price for a booking on this slot.
     * Returns priceOverride if set, otherwise delegates to enquire-button.tsx.price.
     */
    public BigDecimal getEffectivePrice() {
        return priceOverride != null ? priceOverride : tour.getPrice();
    }

    /**
     * Effective currency for a booking on this slot.
     * Returns currency if set (only meaningful alongside priceOverride),
     * otherwise delegates to enquire-button.tsx.currency.
     */
    public TourCurrency getEffectiveCurrency() {
        return currency != null ? currency : tour.getCurrency();
    }
}