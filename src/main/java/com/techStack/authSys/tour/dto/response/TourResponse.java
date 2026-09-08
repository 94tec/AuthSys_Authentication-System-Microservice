package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.*;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record TourResponse(
        UUID id,
        String name,
        String slug,
        String shortDescription,
        String description,
        TourCategory category,

        String destination,
        String country,
        String region,
        String meetingPoint,

        Integer durationDays,
        Integer durationNights,
        TourDifficulty difficulty,
        Integer minimumAge,
        Integer maxGroupSize,
        String bestSeason,

        BigDecimal price,
        TourCurrency currency,
        TourPriceType priceType,
        BigDecimal depositPercentage,

        List<String> highlights,
        List<String> itinerary,
        List<String> inclusions,
        List<String> exclusions,
        List<String> requirements,
        String importantInformation,

        String coverImage,
        List<String> galleryImages,
        String videoUrl,

        BigDecimal averageRating,
        Long reviewCount,

        Boolean active,
        Boolean featured,

        Instant createdDate,
        Instant lastModifiedDate
) {
}