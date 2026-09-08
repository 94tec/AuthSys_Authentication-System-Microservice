package com.techStack.authSys.booking.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Payment lifecycle for a Booking — deliberately kept separate from
 * BookingStatus. The trip lifecycle (PENDING/CONFIRMED/CANCELLED/COMPLETED/
 * NO_SHOW) and the money lifecycle (UNPAID/PARTIALLY_PAID/PAID/REFUNDED)
 * vary independently: a CONFIRMED booking can sit at PARTIALLY_PAID (deposit
 * only) for weeks before the balance is settled, and a CANCELLED booking
 * can be PAID (refund pending) or REFUNDED (refund issued).
 *
 * Transitions, driven by Booking.recordPayment() / Booking.refundPayment():
 *   UNPAID | PARTIALLY_PAID → PARTIALLY_PAID   payment received, amountPaid < totalPrice
 *   UNPAID | PARTIALLY_PAID → PAID              cumulative amountPaid >= totalPrice
 *   PARTIALLY_PAID | PAID   → REFUNDED          refund issued (booking must be CANCELLED)
 */
@Getter
@RequiredArgsConstructor
public enum PaymentStatus {

    UNPAID("No payment received"),
    PARTIALLY_PAID("Deposit received — balance outstanding"),
    PAID("Paid in full"),
    REFUNDED("Payment refunded to customer");

    private final String description;
}