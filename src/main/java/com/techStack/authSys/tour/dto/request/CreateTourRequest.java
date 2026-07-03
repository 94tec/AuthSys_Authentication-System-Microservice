package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourDifficulty;
import jakarta.validation.constraints.*;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
public class CreateTourRequest {

    @NotBlank(message = "Tour name is required")
    @Size(min = 3, max = 150, message = "Name must be between 3 and 150 characters")
    private String name;

    @NotBlank(message = "Description is required")
    @Size(max = 5000)
    private String description;

    @Size(max = 1000)
    private String shortDescription;

    @NotNull(message = "Price per person is required")
    @DecimalMin(value = "0.00", message = "Price must be positive")
    private BigDecimal pricePerPerson;

    @NotNull(message = "Max capacity is required")
    @Min(value = 1, message = "Capacity must be at least 1")
    @Max(value = 500)
    private Integer maxCapacity;

    @NotNull(message = "Duration is required")
    @Min(value = 1, message = "Duration must be at least 1 hour")
    private Integer durationHours;

    @NotNull(message = "Category is required")
    private TourCategory category;

    @NotNull(message = "Difficulty is required")
    private TourDifficulty difficulty;

    @NotBlank(message = "Departure location is required")
    private String departureLocation;

    @NotBlank(message = "Destination is required")
    private String destination;

    private List<String> imageUrls;
    private List<String> inclusions;
    private List<String> exclusions;
    private List<String> highlights;

    private Integer minAge;
    private Integer maxGroupSize;
    private boolean featured;
}
