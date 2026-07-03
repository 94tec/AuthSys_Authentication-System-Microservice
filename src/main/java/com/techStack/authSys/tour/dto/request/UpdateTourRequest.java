package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourDifficulty;
import jakarta.validation.constraints.*;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;

/**
 * All fields optional — only non-null fields are applied (patch semantics).
 */
@Data
public class UpdateTourRequest {

    @Size(min = 3, max = 150)
    private String name;

    @Size(max = 5000)
    private String description;

    @Size(max = 1000)
    private String shortDescription;

    @DecimalMin("0.00")
    private BigDecimal pricePerPerson;

    @Min(1) @Max(500)
    private Integer maxCapacity;

    @Min(1)
    private Integer durationHours;

    private TourCategory category;
    private TourDifficulty difficulty;

    private String departureLocation;
    private String destination;

    private List<String> imageUrls;
    private List<String> inclusions;
    private List<String> exclusions;
    private List<String> highlights;

    private Integer minAge;
    private Integer maxGroupSize;
    private Boolean active;
    private Boolean featured;
}
