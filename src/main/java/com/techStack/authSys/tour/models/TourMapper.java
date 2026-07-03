package com.techStack.authSys.tour.models;

import com.techStack.authSys.tour.dto.request.CreateTourRequest;
import com.techStack.authSys.tour.dto.request.UpdateTourRequest;
import com.techStack.authSys.tour.dto.response.TourResponse;
import com.techStack.authSys.tour.dto.response.TourSummaryResponse;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Optional;

@Component
public class TourMapper {

    public Tour toEntity(CreateTourRequest req, String slug) {
        return Tour.builder()
                .name(req.getName().trim())
                .slug(slug)
                .description(req.getDescription().trim())
                .shortDescription(req.getShortDescription())
                .pricePerPerson(req.getPricePerPerson())
                .maxCapacity(req.getMaxCapacity())
                .durationHours(req.getDurationHours())
                .category(req.getCategory())
                .difficulty(req.getDifficulty())
                .departureLocation(req.getDepartureLocation().trim())
                .destination(req.getDestination().trim())
                .imageUrls(Optional.ofNullable(req.getImageUrls()).orElse(new ArrayList<>()))
                .inclusions(Optional.ofNullable(req.getInclusions()).orElse(new ArrayList<>()))
                .exclusions(Optional.ofNullable(req.getExclusions()).orElse(new ArrayList<>()))
                .highlights(Optional.ofNullable(req.getHighlights()).orElse(new ArrayList<>()))
                .minAge(req.getMinAge())
                .maxGroupSize(req.getMaxGroupSize())
                .featured(req.isFeatured())
                .active(true)
                .build();
    }

    public void applyUpdate(Tour tour, UpdateTourRequest req) {
        if (req.getName() != null) tour.setName(req.getName().trim());
        if (req.getDescription() != null) tour.setDescription(req.getDescription().trim());
        if (req.getShortDescription() != null) tour.setShortDescription(req.getShortDescription());
        if (req.getPricePerPerson() != null) tour.setPricePerPerson(req.getPricePerPerson());
        if (req.getMaxCapacity() != null) tour.setMaxCapacity(req.getMaxCapacity());
        if (req.getDurationHours() != null) tour.setDurationHours(req.getDurationHours());
        if (req.getCategory() != null) tour.setCategory(req.getCategory());
        if (req.getDifficulty() != null) tour.setDifficulty(req.getDifficulty());
        if (req.getDepartureLocation() != null) tour.setDepartureLocation(req.getDepartureLocation().trim());
        if (req.getDestination() != null) tour.setDestination(req.getDestination().trim());
        if (req.getImageUrls() != null) tour.setImageUrls(req.getImageUrls());
        if (req.getInclusions() != null) tour.setInclusions(req.getInclusions());
        if (req.getExclusions() != null) tour.setExclusions(req.getExclusions());
        if (req.getHighlights() != null) tour.setHighlights(req.getHighlights());
        if (req.getMinAge() != null) tour.setMinAge(req.getMinAge());
        if (req.getMaxGroupSize() != null) tour.setMaxGroupSize(req.getMaxGroupSize());
        if (req.getActive() != null) tour.setActive(req.getActive());
        if (req.getFeatured() != null) tour.setFeatured(req.getFeatured());
    }

    public TourResponse toResponse(Tour tour) {
        return TourResponse.builder()
                .id(tour.getId())
                .name(tour.getName())
                .slug(tour.getSlug())
                .description(tour.getDescription())
                .shortDescription(tour.getShortDescription())
                .pricePerPerson(tour.getPricePerPerson())
                .maxCapacity(tour.getMaxCapacity())
                .durationHours(tour.getDurationHours())
                .formattedDuration(tour.getFormattedDuration())
                .category(tour.getCategory())
                .categoryDisplayName(tour.getCategory().getDisplayName())
                .difficulty(tour.getDifficulty())
                .difficultyDescription(tour.getDifficulty().getDescription())
                .departureLocation(tour.getDepartureLocation())
                .destination(tour.getDestination())
                .imageUrls(tour.getImageUrls())
                .inclusions(tour.getInclusions())
                .exclusions(tour.getExclusions())
                .highlights(tour.getHighlights())
                .minAge(tour.getMinAge())
                .maxGroupSize(tour.getMaxGroupSize())
                .active(tour.isActive())
                .featured(tour.isFeatured())
                .averageRating(tour.getAverageRating())
                .totalReviews(tour.getTotalReviews())
                .totalBookings(tour.getTotalBookings())
                .createdDate(tour.getCreatedDate())
                .lastModifiedDate(tour.getLastModifiedDate())
                .build();
    }

    public TourSummaryResponse toSummary(Tour tour) {
        String coverImage = (tour.getImageUrls() != null && !tour.getImageUrls().isEmpty())
                ? tour.getImageUrls().get(0)
                : null;

        return TourSummaryResponse.builder()
                .id(tour.getId())
                .name(tour.getName())
                .slug(tour.getSlug())
                .shortDescription(tour.getShortDescription())
                .pricePerPerson(tour.getPricePerPerson())
                .durationHours(tour.getDurationHours())
                .formattedDuration(tour.getFormattedDuration())
                .category(tour.getCategory())
                .categoryDisplayName(tour.getCategory().getDisplayName())
                .difficulty(tour.getDifficulty())
                .destination(tour.getDestination())
                .coverImageUrl(coverImage)
                .featured(tour.isFeatured())
                .averageRating(tour.getAverageRating())
                .totalReviews(tour.getTotalReviews())
                .build();
    }
}
