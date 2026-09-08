package com.techStack.authSys.tour.models;

import com.techStack.authSys.tour.dto.request.CreateTourRequest;
import com.techStack.authSys.tour.dto.request.UpdateTourRequest;
import com.techStack.authSys.tour.dto.response.TourResponse;
import com.techStack.authSys.tour.dto.response.TourSummaryResponse;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class TourMapper {

    public Tour toEntity(CreateTourRequest r, String slug) {
        return Tour.builder()
                .name(r.name())
                .slug(slug)
                .shortDescription(r.shortDescription())
                .description(r.description())
                .category(r.category())
                .destination(r.destination())
                .country(r.country())
                .region(r.region())
                .meetingPoint(r.meetingPoint())
                .durationDays(r.durationDays())
                .durationNights(r.durationNights())
                .difficulty(r.difficulty())
                .minimumAge(r.minimumAge())
                .maxGroupSize(r.maxGroupSize())
                .bestSeason(r.bestSeason())
                .price(r.price())
                .currency(r.currency())
                .priceType(r.priceType())
                .depositPercentage(r.depositPercentage())
                .highlights(r.highlights() != null ? r.highlights() : new java.util.ArrayList<>())
                .itinerary(r.itinerary() != null ? r.itinerary() : new java.util.ArrayList<>())
                .inclusions(r.inclusions() != null ? r.inclusions() : new java.util.ArrayList<>())
                .exclusions(r.exclusions() != null ? r.exclusions() : new java.util.ArrayList<>())
                .requirements(r.requirements() != null ? r.requirements() : new java.util.ArrayList<>())
                .importantInformation(r.importantInformation())
                .coverImage(r.coverImage())
                .galleryImages(r.galleryImages() != null ? r.galleryImages() : new java.util.ArrayList<>())
                .videoUrl(r.videoUrl())
                .active(r.active() != null ? r.active() : true)
                .featured(r.featured() != null ? r.featured() : false)
                .build();
    }

    /** Partial update — only overwrites fields the caller actually sent. */
    public void applyUpdate(Tour tour, UpdateTourRequest r) {
        if (r.name() != null) tour.setName(r.name());
        if (r.shortDescription() != null) tour.setShortDescription(r.shortDescription());
        if (r.description() != null) tour.setDescription(r.description());
        if (r.category() != null) tour.setCategory(r.category());

        if (r.destination() != null) tour.setDestination(r.destination());
        if (r.country() != null) tour.setCountry(r.country());
        if (r.region() != null) tour.setRegion(r.region());
        if (r.meetingPoint() != null) tour.setMeetingPoint(r.meetingPoint());

        if (r.durationDays() != null) tour.setDurationDays(r.durationDays());
        if (r.durationNights() != null) tour.setDurationNights(r.durationNights());
        if (r.difficulty() != null) tour.setDifficulty(r.difficulty());
        if (r.minimumAge() != null) tour.setMinimumAge(r.minimumAge());
        if (r.maxGroupSize() != null) tour.setMaxGroupSize(r.maxGroupSize());
        if (r.bestSeason() != null) tour.setBestSeason(r.bestSeason());

        if (r.price() != null) tour.setPrice(r.price());
        if (r.currency() != null) tour.setCurrency(r.currency());
        if (r.priceType() != null) tour.setPriceType(r.priceType());
        if (r.depositPercentage() != null) tour.setDepositPercentage(r.depositPercentage());

        if (r.highlights() != null) tour.setHighlights(r.highlights());
        if (r.itinerary() != null) tour.setItinerary(r.itinerary());
        if (r.inclusions() != null) tour.setInclusions(r.inclusions());
        if (r.exclusions() != null) tour.setExclusions(r.exclusions());
        if (r.requirements() != null) tour.setRequirements(r.requirements());
        if (r.importantInformation() != null) tour.setImportantInformation(r.importantInformation());

        if (r.coverImage() != null) tour.setCoverImage(r.coverImage());
        if (r.galleryImages() != null) tour.setGalleryImages(r.galleryImages());
        if (r.videoUrl() != null) tour.setVideoUrl(r.videoUrl());

        if (r.active() != null) tour.setActive(r.active());
        if (r.featured() != null) tour.setFeatured(r.featured());
    }

    public TourResponse toResponse(Tour t) {
        return new TourResponse(
                t.getId(), t.getName(), t.getSlug(), t.getShortDescription(), t.getDescription(), t.getCategory(),
                t.getDestination(), t.getCountry(), t.getRegion(), t.getMeetingPoint(),
                t.getDurationDays(), t.getDurationNights(), t.getDifficulty(), t.getMinimumAge(), t.getMaxGroupSize(), t.getBestSeason(),
                t.getPrice(), t.getCurrency(), t.getPriceType(), t.getDepositPercentage(),
                t.getHighlights(), t.getItinerary(), t.getInclusions(), t.getExclusions(), t.getRequirements(), t.getImportantInformation(),
                t.getCoverImage(), t.getGalleryImages(), t.getVideoUrl(),                t.getAverageRating(), t.getReviewCount(),
                t.getActive(), t.getFeatured(),                t.getCreatedDate(), t.getLastModifiedDate()        );
    }

    public TourResponse to_Response(Tour t) {
        return new TourResponse(
                t.getId(), t.getName(), t.getSlug(), t.getShortDescription(), t.getDescription(), t.getCategory(),
                t.getDestination(), t.getCountry(), t.getRegion(), t.getMeetingPoint(),
                t.getDurationDays(), t.getDurationNights(), t.getDifficulty(), t.getMinimumAge(), t.getMaxGroupSize(), t.getBestSeason(),
                t.getPrice(), t.getCurrency(), t.getPriceType(), t.getDepositPercentage(),
                List.copyOf(t.getHighlights()), List.copyOf(t.getItinerary()), List.copyOf(t.getInclusions()),
                List.copyOf(t.getExclusions()), List.copyOf(t.getRequirements()), t.getImportantInformation(),
                t.getCoverImage(), List.copyOf(t.getGalleryImages()), t.getVideoUrl(),
                t.getAverageRating(), t.getReviewCount(),
                t.getActive(), t.getFeatured(),
                t.getCreatedDate(), t.getLastModifiedDate()
        );
    }

    public TourSummaryResponse toSummary(Tour t) {
        return new TourSummaryResponse(
                t.getId(), t.getName(), t.getSlug(), t.getShortDescription(), t.getCategory(),
                t.getDestination(), t.getCountry(), t.getDurationDays(), t.getDifficulty(),
                t.getPrice(), t.getCurrency(), t.getCoverImage(),
                t.getAverageRating(), t.getReviewCount(), t.getFeatured(), t.getActive()
        );
    }
}