package com.techStack.authSys.payment.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.UUID;

/**
 * Customer-facing request to initiate an M-Pesa STK push.
 * POST /api/payments/mpesa/stk-push
 *
 * The amount is NOT supplied by the client — it is read from the booking
 * in PaymentService to prevent tampering.
 */
public record StkPushRequest(

        @NotNull(message = "Booking ID is required")
        UUID bookingId,

        /**
         * Phone number to send the STK push to.
         * Format: 2547XXXXXXXX (Kenyan number, no leading + or spaces).
         * Validated against the E.164 pattern for Kenya.
         */
        @NotBlank(message = "Phone number is required")
        @Pattern(
            regexp = "^2547\\d{8}$",
            message = "Phone number must be in format 2547XXXXXXXX"
        )
        String phoneNumber,

        /**
         * Short description shown on the M-Pesa prompt.
         * Max 12 chars — Daraja truncates silently if longer.
         * Defaults to "Tour Booking" in PaymentService if null.
         */
        String description

) {}
