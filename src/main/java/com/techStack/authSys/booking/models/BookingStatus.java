package com.techStack.authSys.booking.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum BookingStatus {

    PENDING_PAYMENT("Awaiting payment to confirm booking"),
    CONFIRMED("Booking confirmed and paid"),
    CANCELLED("Booking cancelled"),
    COMPLETED("Tour completed successfully"),
    REFUNDED("Payment refunded to customer");

    private final String description;

    /**
     * Whether this booking can still be cancelled.
     * COMPLETED and REFUNDED bookings are terminal — not cancellable.
     */
    public boolean isCancellable() {
        return this == PENDING_PAYMENT || this == CONFIRMED;
    }

    /**
     * Whether this booking occupies an availability slot.
     * Used to determine whether slot counts should be considered.
     */
    public boolean isActive() {
        return this == PENDING_PAYMENT || this == CONFIRMED;
    }

    /**
     * Whether this booking is in a terminal state
     * (no further lifecycle transitions possible).
     */
    public boolean isTerminal() {
        return this == COMPLETED || this == REFUNDED;
    }
}