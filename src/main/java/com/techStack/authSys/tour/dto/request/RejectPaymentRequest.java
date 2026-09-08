package com.techStack.authSys.tour.dto.request;

import jakarta.validation.constraints.NotBlank;

public record RejectPaymentRequest(
        @NotBlank String reason
) {}