package com.techStack.authSys.tour.models;

import com.techStack.authSys.common.models.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.BatchSize;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(
        name = "tours",
        indexes = {
                @Index(name = "idx_tour_slug", columnList = "slug"),
                @Index(name = "idx_tour_category", columnList = "category"),
                @Index(name = "idx_tour_active", columnList = "active"),
                @Index(name = "idx_tour_featured", columnList = "featured"),
                @Index(name = "idx_tour_destination", columnList = "destination"),
                @Index(name = "idx_tour_country", columnList = "country"),
                @Index(name = "idx_tour_country_category", columnList = "country, category")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Tour extends BaseEntity {

    // ── Identity ──────────────────────────────────────────────
    @Column(nullable = false, length = 150)
    private String name;

    @Column(nullable = false, unique = true, length = 180)
    private String slug;

    @Column(nullable = false, length = 500)
    private String shortDescription;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private TourCategory category;

    // ── Destination ───────────────────────────────────────────
    @Column(nullable = false, length = 150)
    private String destination;

    @Column(nullable = false, length = 100)
    private String country;

    @Column(length = 150)
    private String region;

    @Column(length = 300)
    private String meetingPoint;

    // ── Trip details ──────────────────────────────────────────
    @Column(nullable = false)
    private Integer durationDays;

    @Column(nullable = false)
    private Integer durationNights;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private TourDifficulty difficulty;

    private Integer minimumAge;

    private Integer maxGroupSize;

    @Column(length = 200)
    private String bestSeason;

    // ── Pricing ───────────────────────────────────────────────
    @Column(nullable = false, precision = 12, scale = 2)
    private BigDecimal price;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 3)
    private TourCurrency currency;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private TourPriceType priceType;

    @Column(precision = 5, scale = 2)
    private BigDecimal depositPercentage;

    // ── Content ───────────────────────────────────────────────

    @ElementCollection
    @CollectionTable(name = "tour_highlights", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "highlight", nullable = false)
    @BatchSize(size = 25)
    @Builder.Default
    private List<String> highlights = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "tour_itinerary", joinColumns = @JoinColumn(name = "tour_id"))
    @OrderColumn(name = "day_order")
    @Column(name = "activity", nullable = false)
    @BatchSize(size = 25)
    @Builder.Default
    private List<String> itinerary = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "tour_inclusions", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "inclusion", nullable = false)
    @BatchSize(size = 25)
    @Builder.Default
    private List<String> inclusions = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "tour_exclusions", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "exclusion", nullable = false)
    @BatchSize(size = 25)
    @Builder.Default
    private List<String> exclusions = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "tour_requirements", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "requirement", nullable = false)
    @BatchSize(size = 25)
    @Builder.Default
    private List<String> requirements = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "tour_gallery", joinColumns = @JoinColumn(name = "tour_id"))
    @Column(name = "image_url", nullable = false)
    @BatchSize(size = 25)
    @Builder.Default
    private List<String> galleryImages = new ArrayList<>();

    @Column(columnDefinition = "TEXT")
    private String importantInformation;

    // ── Media ─────────────────────────────────────────────────
    @Column(nullable = false, length = 1000)
    private String coverImage;


    @Column(length = 1000)
    private String videoUrl;

    // ── Ratings ───────────────────────────────────────────────
    @Builder.Default
    @Column(nullable = false, precision = 3, scale = 2)
    private BigDecimal averageRating = BigDecimal.ZERO;

    @Builder.Default
    @Column(nullable = false)
    private Long reviewCount = 0L;

    // ── Publishing ────────────────────────────────────────────
    @Builder.Default
    @Column(nullable = false)
    private Boolean active = true;

    @Builder.Default
    @Column(nullable = false)
    private Boolean featured = false;
}