package com.techStack.authSys.payment.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Lifecycle states of a Payment record.
 *
 * Flow:
 *   PENDING  → SUCCESS  (M-Pesa callback ResultCode = 0)
 *           ↘ FAILED    (callback ResultCode != 0, or STK timeout)
 *           ↘ CANCELLED (customer dismissed STK push)
 *   SUCCESS  → REFUNDED (ADMIN triggers refund after booking cancellation)
 *
 * A Payment row is created when the STK push is initiated (PENDING).
 * PaymentService.handleMpesaCallback() transitions it to SUCCESS or FAILED.
 * On SUCCESS, PaymentService calls BookingService.confirmBooking().
 */
@Getter
@RequiredArgsConstructor
public enum PaymentStatus {

    PENDING("STK push sent — awaiting customer confirmation"),
    SUCCESS("Payment received and verified"),
    FAILED("Payment failed or timed out"),
    CANCELLED("Customer cancelled the payment prompt"),
    REFUNDED("Payment refunded to customer");

    private final String description;
}
