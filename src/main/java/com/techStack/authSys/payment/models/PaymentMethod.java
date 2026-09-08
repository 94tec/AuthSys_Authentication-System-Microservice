package com.techStack.authSys.payment.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Payment method used to settle a booking.
 *
 * MPESA        — Safaricom M-Pesa Daraja STK Push (primary, Kenya)
 * CARD         — Card via Flutterwave or Pesapal (Phase 2)
 * BANK_TRANSFER— Manual bank transfer confirmed by ADMIN (Phase 2)
 * CASH         — In-person cash, logged by MANAGER (Phase 2)
 */
@Getter
@RequiredArgsConstructor
public enum PaymentMethod {
    MPESA("M-Pesa (Safaricom)"),
    CARD("Card Payment"),
    BANK_TRANSFER("Bank Transfer"),
    CASH("Cash");

    private final String displayName;
}
