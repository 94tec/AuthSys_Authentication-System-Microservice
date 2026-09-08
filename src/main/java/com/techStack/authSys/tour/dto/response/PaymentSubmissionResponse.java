package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.PaymentChannel;
import com.techStack.authSys.tour.models.PaymentSubmissionStatus;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

public record PaymentSubmissionResponse(
        UUID id,
        UUID quoteId,
        UUID enquiryId,
        UUID tourId,
        String customerName,
        String tourName,
        PaymentChannel channel,
        String referenceCode,
        BigDecimal amountPaid,
        BigDecimal quoteTotal,
        String currency,
        Integer adultCount,
        Integer childCount,
        String payerName,
        PaymentSubmissionStatus status,
        String verifiedBy,
        Instant verifiedAt,
        String rejectionReason,
        String bookingReference,
        Instant createdDate,
        boolean isBalancePayment
) {}
