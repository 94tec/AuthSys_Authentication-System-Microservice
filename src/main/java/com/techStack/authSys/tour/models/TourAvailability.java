package com.techStack.authSys.tour.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDate;
import java.time.OffsetDateTime;

/**
 * A bookable date slot for a specific Tour.
 *
 * One tour can have many availability slots — one per departure date.
 * Created by DESIGNER or MANAGER via AvailabilityController.
 *
 * ─── Critical contract with BookingService ───────────────────────────────────
 * BookingService calls these methods directly — signatures must not change:
 *
 *   slot.getStatus()                 → AvailabilityStatus (checked == OPEN)
 *   slot.getBookingDeadline()        → OffsetDateTime (null = no deadline)
 *   slot.getDate()                   → LocalDate
 *   slot.getAvailableSlots()         → Integer (remaining capacity)
 *   slot.hasAvailability(int count)  → boolean (capacity guard)
 *   slot.reserveSlots(int count)     → void (mutates + updates status)
 *   slot.releaseSlots(int count)     → void (on cancellation)
 *   slot.getTour().getId()           → UUID (validates slot belongs to tour)
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * @Version on BaseEntity provides optimistic locking — concurrent booking
 * attempts on the last slot(s) result in OptimisticLockingFailureException,
 * caught in BookingService and converted to HTTP 409.
 */
@Entity
@Table(
        name = "tour_availability",
        indexes = {
                @Index(name = "idx_availability_tour",   columnList = "tour_id"),
                @Index(name = "idx_availability_date",   columnList = "date"),
                @Index(name = "idx_availability_status", columnList = "status"),
                @Index(name = "idx_availability_tour_date",
                        columnList = "tour_id, date", unique = true)
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TourAvailability extends BaseEntity {

    // ── Core ────────────────────────────────────────────────────────────────

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tour_id", nullable = false, updatable = false)
    private Tour tour;

    /**
     * Departure / tour date.
     * Unique per tour — one slot per date. Enforced by unique index above.
     */
    @NotNull
    @Column(name = "date", nullable = false, updatable = false)
    private LocalDate date;

    // ── Capacity ─────────────────────────────────────────────────────────────

    /**
     * Total seats available when this slot was opened.
     * Typically mirrors tour.maxCapacity but can be overridden per date
     * (e.g. smaller vehicle for a specific departure).
     */
    @NotNull
    @Min(1)
    @Column(name = "max_slots", nullable = false)
    private Integer maxSlots;

    /**
     * Remaining bookable seats.
     * Decremented by reserveSlots(), incremented by releaseSlots().
     * Reaching 0 triggers status → FULL.
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

    /**
     * Optional deadline after which no new bookings are accepted.
     * BookingService checks: OffsetDateTime.now().isAfter(bookingDeadline).
     * Null means no deadline — bookings accepted up to the day itself.
     */
    @Column(name = "booking_deadline")
    private OffsetDateTime bookingDeadline;

    /**
     * Optional price override for this specific date.
     * If null, booking uses tour.pricePerPerson.
     * Reserved for peak-season pricing (Phase 2).
     */
    @Column(name = "price_override", precision = 10, scale = 2)
    private java.math.BigDecimal priceOverride;

    /**
     * Internal notes for operations staff — not visible to customers.
     * e.g. "School group confirmed for AM slot", "VIP clients only".
     */
    @Column(name = "internal_notes", length = 500)
    private String internalNotes;

    // ── Domain methods ───────────────────────────────────────────────────────

    /**
     * Check if this slot can accept the requested number of travelers.
     * Called in BookingService.createBooking() step 7 (primary capacity guard).
     *
     * @param count number of travelers requested
     * @return true if availableSlots >= count AND status == OPEN
     */
    public boolean hasAvailability(int count) {
        return status == AvailabilityStatus.OPEN && availableSlots >= count;
    }

    /**
     * Reserve seats — called in BookingService.createBooking() step 13.
     * Decrements availableSlots and flips status to FULL when slots reach 0.
     *
     * This is the second guard (after hasAvailability) — throws
     * IllegalStateException if somehow called when capacity is insufficient.
     * BookingService catches IllegalStateException → HTTP 409.
     *
     * @param count number of seats to reserve
     * @throws IllegalStateException if insufficient slots (fallback guard)
     */
    public void reserveSlots(int count) {
        if (availableSlots < count) {
            throw new IllegalStateException(
                    "Cannot reserve " + count + " slots — only " + availableSlots + " available");
        }
        this.availableSlots -= count;
        if (this.availableSlots == 0) {
            this.status = AvailabilityStatus.FULL;
        }
    }

    /**
     * Release seats back to the slot — called on booking cancellation.
     * Increments availableSlots and re-opens status if it was FULL.
     * Cannot exceed maxSlots (guard against data corruption).
     *
     * @param count number of seats to release
     */
    public void releaseSlots(int count) {
        this.availableSlots = Math.min(this.availableSlots + count, this.maxSlots);
        if (this.status == AvailabilityStatus.FULL && this.availableSlots > 0) {
            this.status = AvailabilityStatus.OPEN;
        }
    }

    /**
     * Manually close this slot — called by MANAGER/DESIGNER.
     * Slots with CLOSED status are not bookable.
     */
    public void close() {
        this.status = AvailabilityStatus.CLOSED;
    }

    /**
     * Reopen a previously CLOSED slot.
     * Only valid if there are still slots available.
     */
    public void reopen() {
        if (availableSlots > 0) {
            this.status = AvailabilityStatus.OPEN;
        }
    }

    /**
     * Convenience: booked seats count (maxSlots - availableSlots).
     */
    public int getBookedCount() {
        return maxSlots - availableSlots;
    }

    /**
     * Occupancy as a percentage — used in analytics.
     */
    public double getOccupancyPercent() {
        if (maxSlots == 0) return 0;
        return (double) getBookedCount() / maxSlots * 100;
    }
}
