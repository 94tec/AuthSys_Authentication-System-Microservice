package com.techStack.authSys.payment.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * Returned immediately to the customer after POST /api/payments/mpesa/stk-push.
 *
 * The STK push is async — this response tells the customer:
 *   "Check your phone and enter your M-Pesa PIN."
 *
 * The frontend polls GET /api/payments/{paymentId}/status until
 * status transitions from PENDING to SUCCESS or FAILED.
 */
@Data
@Builder
public class StkPushResponse {

    /** Internal payment record ID — used to poll for status. */
    private UUID      paymentId;

    /** Safaricom's CheckoutRequestID — used for STK query if needed. */
    private String    checkoutRequestId;

    /** Phone number the push was sent to. */
    private String    phoneNumber;

    /** Amount charged. */
    private BigDecimal amount;

    /** Always "PENDING" at this point. */
    private String    status;

    /** Message to display to the customer. */
    private String    message;
}
