package com.techStack.authSys.payment.dto.response;

import com.techStack.authSys.payment.models.PaymentStatus;
import lombok.Builder;
import lombok.Data;

import java.util.UUID;

/**
 * Lightweight status response — used by the frontend polling loop.
 * GET /api/payments/{paymentId}/status
 *
 * Frontend logic:
 *   while (status == PENDING) { sleep(3s); poll(); }
 *   if (status == SUCCESS)  → show booking confirmation
 *   if (status == FAILED)   → show retry button
 *   if (status == CANCELLED)→ show "You cancelled" message
 */
@Data
@Builder
public class PaymentStatusResponse {
    private UUID          paymentId;
    private PaymentStatus status;
    private String        statusDescription;
    private String        mpesaReceiptNumber; // non-null only on SUCCESS
    private String        message;            // user-friendly message
}
