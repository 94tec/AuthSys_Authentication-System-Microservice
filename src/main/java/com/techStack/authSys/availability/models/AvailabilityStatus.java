package com.techStack.authSys.availability.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Status of a TourAvailability slot.
 *
 * Transitions (all capacity-driven ones go through
 * TourAvailability.computeCapacityStatus()):
 *   OPEN    → LIMITED     availableSlots drops to/below the low-availability threshold
 *   LIMITED → OPEN        availableSlots rises back above the threshold (release)
 *   OPEN | LIMITED → FULL availableSlots reaches 0 via reserveSlots()
 *   FULL → OPEN | LIMITED when a booking is cancelled via releaseSlots()
 *   OPEN | LIMITED | FULL → CLOSED    manual close by OPERATOR/MANAGER
 *   OPEN | LIMITED | FULL → CANCELLED enquire-button.tsx date cancelled by ADMIN
 *   CLOSED → OPEN | LIMITED | FULL    manual reopen (status recalculated from capacity)
 *
 * IMPORTANT — BookingService integration:
 *   LIMITED slots are still bookable. BookingService must call
 *   slot.hasAvailability(count) rather than comparing
 *   slot.getStatus() == OPEN directly, or LIMITED slots will be
 *   incorrectly treated as unbookable.
 */
@Getter
@RequiredArgsConstructor
public enum AvailabilityStatus {

    OPEN("Accepting bookings"),
    LIMITED("Filling up — few slots remaining"),
    FULL("No slots remaining"),
    CLOSED("Closed by staff — not accepting bookings"),
    CANCELLED("Tour date cancelled");

    private final String description;
}