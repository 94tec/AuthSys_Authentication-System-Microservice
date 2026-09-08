package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.TourCurrency;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.time.LocalDate;


public record CreateQuoteRequest(
        @NotNull @PositiveOrZero Integer adultCount,

        @NotNull @PositiveOrZero Integer childCount,

        @NotNull @Positive BigDecimal pricePerAdult,

        @PositiveOrZero BigDecimal pricePerChild,

        @NotNull TourCurrency currency,

        @NotNull @Future LocalDate validUntil,

        String inclusionsNote,

        String internalNote
) {}



