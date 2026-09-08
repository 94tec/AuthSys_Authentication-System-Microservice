package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.QuoteStatus;

import java.util.Set;
import java.util.UUID;

public record QuoteStatusErrorResponse(
        boolean success,
        int status,
        String errorCode,
        String message,
        UUID quoteId,
        QuoteStatus currentStatus,
        Set<QuoteStatus> allowedStatuses,
        String action
) {}