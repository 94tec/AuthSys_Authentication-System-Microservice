package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourCurrency;
import com.techStack.authSys.tour.models.TourDifficulty;
import com.techStack.authSys.tour.models.TourPriceType;
import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.util.List;

public record CreateTourRequest(

        // ── Identity ──────────────────────────────────────────
        @NotBlank(message = "Tour name is required")
        @Size(max = 150, message = "Tour name must not exceed 150 characters")
        String name,

        @NotBlank(message = "Short description is required")
        @Size(max = 500, message = "Short description must not exceed 500 characters")
        String shortDescription,

        @NotBlank(message = "Tour description is required")
        @Size(max = 10000, message = "Description must not exceed 10,000 characters")
        String description,

        @NotNull(message = "Tour category is required")
        TourCategory category,

        // ── Destination ───────────────────────────────────────
        @NotBlank(message = "Destination is required")
        @Size(max = 150)
        String destination,

        @NotBlank(message = "Country is required")
        @Size(max = 100)
        String country,

        @Size(max = 150)
        String region,

        @Size(max = 300)
        String meetingPoint,

        // ── Trip details ─────────────────────────────────────
        @NotNull(message = "Duration in days is required")
        @Min(value = 1, message = "Duration must be at least 1 day")
        @Max(value = 365, message = "Duration cannot exceed 365 days")
        Integer durationDays,

        @NotNull(message = "Duration in nights is required")
        @Min(value = 0, message = "Duration nights cannot be negative")
        Integer durationNights,

        @NotNull(message = "Difficulty is required")
        TourDifficulty difficulty,

        @Min(value = 1, message = "Minimum age must be at least 1")
        Integer minimumAge,

        @Min(value = 1, message = "Maximum group size must be at least 1")
        @Max(value = 1000, message = "Maximum group size cannot exceed 1000")
        Integer maxGroupSize,

        @Size(max = 200)
        String bestSeason,

        // ── Pricing ───────────────────────────────────────────
        @NotNull(message = "Price is required")
        @DecimalMin(value = "0.00", inclusive = true, message = "Price cannot be negative")
        @Digits(integer = 10, fraction = 2, message = "Invalid price format")
        BigDecimal price,

        @NotNull(message = "Currency is required")
        TourCurrency currency,

        @NotNull(message = "Price type is required")
        TourPriceType priceType,

        @DecimalMin(value = "0.00")
        @DecimalMax(value = "100.00")
        BigDecimal depositPercentage,

        // ── Content ───────────────────────────────────────────
        @Size(max = 20, message = "Maximum 20 highlights allowed")
        List<@NotBlank String> highlights,

        @Size(max = 50, message = "Maximum 50 itinerary items allowed")
        List<@NotBlank String> itinerary,

        @Size(max = 50, message = "Maximum 50 inclusions allowed")
        List<@NotBlank String> inclusions,

        @Size(max = 50, message = "Maximum 50 exclusions allowed")
        List<@NotBlank String> exclusions,

        @Size(max = 50, message = "Maximum 50 requirements allowed")
        List<@NotBlank String> requirements,

        @Size(max = 5000)
        String importantInformation,

        // ── Media ─────────────────────────────────────────────
        @NotBlank(message = "Cover image is required")
        @Size(max = 1000)
        String coverImage,

        @Size(max = 30, message = "Maximum 30 gallery images allowed")
        List<@NotBlank String> galleryImages,

        @Size(max = 1000)
        String videoUrl,

        // ── Publishing ────────────────────────────────────────
        Boolean active,
        Boolean featured
) {
}