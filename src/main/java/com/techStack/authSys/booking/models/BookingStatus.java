package com.techStack.authSys.booking.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Trip lifecycle for a Booking. Deliberately excludes payment concepts —
 * PARTIALLY_PAID / PAID / REFUNDED now live on PaymentStatus instead, since
 * the two dimensions vary independently (see PaymentStatus javadoc).
 */
@Getter
@RequiredArgsConstructor
public enum BookingStatus {

    PENDING_PAYMENT("Awaiting confirmation"),
    CONFIRMED("Booking confirmed"),
    CANCELLED("Booking cancelled"),
    COMPLETED("Tour completed successfully"),
    NO_SHOW("Customer did not show up for the enquire-button.tsx");

    private final String description;

    /**
     * Whether this booking can still be cancelled.
     * COMPLETED, CANCELLED, and NO_SHOW are terminal — not cancellable.
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
        return this == COMPLETED || this == CANCELLED || this == NO_SHOW;
    }
}