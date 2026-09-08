package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourCurrency;
import com.techStack.authSys.tour.models.TourDifficulty;

import java.math.BigDecimal;
import java.util.UUID;

/** Lightweight shape for grid/card views — no itinerary, gallery, or long-form content. */
public record TourSummaryResponse(
        UUID id,
        String name,
        String slug,
        String shortDescription,
        TourCategory category,
        String destination,
        String country,
        Integer durationDays,
        TourDifficulty difficulty,
        BigDecimal price,
        TourCurrency currency,
        String coverImage,
        BigDecimal averageRating,
        Long reviewCount,
        Boolean featured,
        Boolean active
) {
}