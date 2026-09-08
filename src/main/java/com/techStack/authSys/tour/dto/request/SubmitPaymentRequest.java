package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.PaymentChannel;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;

public record SubmitPaymentRequest(
        @NotNull PaymentChannel channel,
        @NotBlank @Size(max = 100) String referenceCode,
        @NotNull @Positive BigDecimal amountPaid,
        @Size(max = 150) String payerName
) {}