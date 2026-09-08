package com.techStack.authSys.payment.dto.response;

import com.techStack.authSys.payment.models.PaymentMethod;
import com.techStack.authSys.payment.models.PaymentStatus;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Full payment record response — returned to staff and admin.
 * Customer-facing views get StkPushResponse instead.
 */
@Data
@Builder
public class PaymentResponse {

    private UUID          id;
    private UUID          bookingId;
    private String        customerId;

    private BigDecimal    amount;
    private String        currency;

    private PaymentMethod method;
    private PaymentStatus status;
    private String        statusDescription;

    // M-Pesa specific
    private String        phoneNumber;
    private String        checkoutRequestId;
    private String        merchantRequestId;
    private String        mpesaReceiptNumber;
    private Integer       resultCode;
    private String        resultDescription;

    private OffsetDateTime initiatedAt;
    private OffsetDateTime completedAt;
}
