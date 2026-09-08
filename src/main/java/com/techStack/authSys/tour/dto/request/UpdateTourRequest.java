package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourCurrency;
import com.techStack.authSys.tour.models.TourDifficulty;
import com.techStack.authSys.tour.models.TourPriceType;
import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.util.List;

public record UpdateTourRequest(
        @Size(max = 150) String name,
        @Size(max = 500) String shortDescription,
        @Size(max = 10000) String description,
        TourCategory category,

        @Size(max = 150) String destination,
        @Size(max = 100) String country,
        @Size(max = 150) String region,
        @Size(max = 300) String meetingPoint,

        @Min(1) @Max(365) Integer durationDays,
        @Min(0) Integer durationNights,
        TourDifficulty difficulty,
        @Min(1) Integer minimumAge,
        @Min(1) @Max(1000) Integer maxGroupSize,
        @Size(max = 200) String bestSeason,

        @DecimalMin("0.00") @Digits(integer = 10, fraction = 2) BigDecimal price,
        TourCurrency currency,
        TourPriceType priceType,
        @DecimalMin("0.00") @DecimalMax("100.00") BigDecimal depositPercentage,

        @Size(max = 20) List<@NotBlank String> highlights,
        @Size(max = 50) List<@NotBlank String> itinerary,
        @Size(max = 50) List<@NotBlank String> inclusions,
        @Size(max = 50) List<@NotBlank String> exclusions,
        @Size(max = 50) List<@NotBlank String> requirements,
        @Size(max = 5000) String importantInformation,

        @Size(max = 1000) String coverImage,
        @Size(max = 30) List<@NotBlank String> galleryImages,
        @Size(max = 1000) String videoUrl,

        Boolean active,
        Boolean featured
) {
}