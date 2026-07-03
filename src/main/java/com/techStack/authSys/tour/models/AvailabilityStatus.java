package com.techStack.authSys.tour.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Status of a TourAvailability slot.
 *
 * Transitions:
 *   OPEN → FULL         (when availableSlots reaches 0 via reserveSlots())
 *   FULL → OPEN         (when a booking is cancelled via releaseSlots())
 *   OPEN | FULL → CLOSED (manual close by DESIGNER/MANAGER)
 *   OPEN | FULL → CANCELLED (tour cancelled entirely by ADMIN)
 *
 * BookingService checks: slot.getStatus() == OPEN before allowing a booking.
 */
@Getter
@RequiredArgsConstructor
public enum AvailabilityStatus {

    OPEN("Accepting bookings"),
    LIMITED(""),
    FULL("No slots remaining"),
    CLOSED("Closed by staff — not accepting bookings"),
    SOLD_OUT(""),
    CANCELLED("Tour date cancelled");


    private final String description;
}
