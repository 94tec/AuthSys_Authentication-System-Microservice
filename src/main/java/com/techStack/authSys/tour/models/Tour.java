package com.techStack.authSys.tour.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/**
 * Core Tour entity for Damuchi Safaris.
 * Stored in PostgreSQL. Linked to Availability and Booking.
 */
@Entity
@Table(name = "tours", indexes = {
        @Index(name = "idx_tour_slug", columnList = "slug", unique = true),
        @Index(name = "idx_tour_category", columnList = "category"),
        @Index(name = "idx_tour_active", columnList = "active")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Tour extends BaseEntity {

    @NotBlank
    @Size(min = 3, max = 150)
    @Column(name = "name", nullable = false, length = 150)
    private String name;

    /**
     * URL-friendly unique identifier — e.g. "maasai-mara-3-day-safari"
     * Auto-generated from name on create.
     */
    @NotBlank
    @Column(name = "slug", nullable = false, unique = true, length = 200)
    private String slug;

    @NotBlank
    @Size(max = 5000)
    @Column(name = "description", nullable = false, columnDefinition = "TEXT")
    private String description;

    @Size(max = 1000)
    @Column(name = "short_description", length = 1000)
    private String shortDescription;

    @NotNull
    @DecimalMin("0.00")
    @Column(name = "price_per_person", nullable = false, precision = 10, scale = 2)
    private BigDecimal pricePerPerson;

    @NotNull
    @Min(1)
    @Max(500)
    @Column(name = "max_capacity", nullable = false)
    private Integer maxCapacity;

    /**
     * Duration in hours — e.g. 8 for a day trip, 72 for 3-day safari
     */
    @NotNull
    @Min(1)
    @Column(name = "duration_hours", nullable = false)
    private Integer durationHours;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "category", nullable = false, length = 50)
    private TourCategory category;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "difficulty", nullable = false, length = 20)
    private TourDifficulty difficulty;

    /**
     * Departure/meeting point — e.g. "Nairobi CBD, Anniversary Towers"
     */
    @NotBlank
    @Column(name = "departure_location", nullable = false, length = 300)
    private String departureLocation;

    /**
     * Main destination — e.g. "Maasai Mara National Reserve"
     */
    @NotBlank
    @Column(name = "destination", nullable = false, length = 300)
    private String destination;

    /**
     * Comma-separated image URLs or stored as JSON array.
     * For Phase 2: migrate to a TourImage child table.
     */
    @ElementCollection
    @CollectionTable(name = "tour_images", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "image_url", length = 500)
    @Builder.Default
    private List<String> imageUrls = new ArrayList<>();

    /**
     * What's included — e.g. ["Transport", "Meals", "Park fees"]
     */
    @ElementCollection
    @CollectionTable(name = "tour_inclusions", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "inclusion", length = 200)
    @Builder.Default
    private List<String> inclusions = new ArrayList<>();

    /**
     * What's excluded — e.g. ["Tips", "Travel insurance"]
     */
    @ElementCollection
    @CollectionTable(name = "tour_exclusions", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "exclusion", length = 200)
    @Builder.Default
    private List<String> exclusions = new ArrayList<>();

    /**
     * Highlights — e.g. ["Big Five game drive", "Mara River crossing"]
     */
    @ElementCollection
    @CollectionTable(name = "tour_highlights", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "highlight", length = 300)
    @Builder.Default
    private List<String> highlights = new ArrayList<>();

    @Column(name = "min_age")
    private Integer minAge;

    @Column(name = "max_group_size")
    private Integer maxGroupSize;

    /**
     * Whether this tour is visible and bookable on the site.
     */
    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = true;

    /**
     * Featured tours appear on the homepage.
     */
    @Column(name = "featured", nullable = false)
    @Builder.Default
    private boolean featured = false;

    /**
     * Average rating — updated via a scheduled job from confirmed booking reviews.
     */
    @Column(name = "average_rating", precision = 3, scale = 2)
    private BigDecimal averageRating;

    @Column(name = "total_reviews")
    @Builder.Default
    private Integer totalReviews = 0;

    @Column(name = "total_bookings")
    @Builder.Default
    private Integer totalBookings = 0;

    // ─── Convenience ────────────────────────────────────────────────────────

    public String getFormattedDuration() {
        if (durationHours < 24) return durationHours + " hours";
        int days = durationHours / 24;
        int hours = durationHours % 24;
        return hours == 0 ? days + " day" + (days > 1 ? "s" : "")
                : days + " day" + (days > 1 ? "s" : "") + " " + hours + "h";
    }
}
