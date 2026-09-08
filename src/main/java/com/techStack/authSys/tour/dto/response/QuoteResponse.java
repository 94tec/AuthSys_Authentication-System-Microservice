package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.QuoteStatus;
import com.techStack.authSys.tour.models.TourCurrency;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record QuoteResponse(
        UUID id,
        UUID enquiryId,

        Integer adultCount,
        Integer childCount,

        BigDecimal pricePerAdult,
        BigDecimal pricePerChild,
        BigDecimal totalPrice,

        TourCurrency currency,
        LocalDate validUntil,

        String inclusionsNote,
        QuoteStatus status,

        Instant sentAt,
        Instant respondedAt
) {}


