package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourDifficulty;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class TourResponse {
    private UUID id;
    private String name;
    private String slug;
    private String description;
    private String shortDescription;
    private BigDecimal pricePerPerson;
    private Integer maxCapacity;
    private Integer durationHours;
    private String formattedDuration;
    private TourCategory category;
    private String categoryDisplayName;
    private TourDifficulty difficulty;
    private String difficultyDescription;
    private String departureLocation;
    private String destination;
    private List<String> imageUrls;
    private List<String> inclusions;
    private List<String> exclusions;
    private List<String> highlights;
    private Integer minAge;
    private Integer maxGroupSize;
    private boolean active;
    private boolean featured;
    private BigDecimal averageRating;
    private Integer totalReviews;
    private Integer totalBookings;
    private Instant createdDate;
    private Instant lastModifiedDate;
}
