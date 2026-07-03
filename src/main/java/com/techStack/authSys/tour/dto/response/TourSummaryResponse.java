package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourDifficulty;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

/**
 * Lightweight response for tour listing pages and search results.
 * Excludes full description, inclusions/exclusions to keep payload small.
 */
@Data
@Builder
public class TourSummaryResponse {
    private UUID id;
    private String name;
    private String slug;
    private String shortDescription;
    private BigDecimal pricePerPerson;
    private Integer durationHours;
    private String formattedDuration;
    private TourCategory category;
    private String categoryDisplayName;
    private TourDifficulty difficulty;
    private String destination;
    private String coverImageUrl;       // first image in imageUrls
    private boolean featured;
    private BigDecimal averageRating;
    private Integer totalReviews;
}
