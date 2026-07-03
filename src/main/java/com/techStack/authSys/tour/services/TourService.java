package com.techStack.authSys.tour.service;

import com.techStack.authSys.exception.resource.DuplicateResourceException;
import com.techStack.authSys.exception.resource.ResourceNotFoundException;
import com.techStack.authSys.tour.dto.request.CreateTourRequest;
import com.techStack.authSys.tour.dto.request.UpdateTourRequest;
import com.techStack.authSys.tour.dto.response.TourResponse;
import com.techStack.authSys.tour.dto.response.TourSummaryResponse;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.models.TourMapper;
import com.techStack.authSys.tour.repository.TourRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.text.Normalizer;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Tour service — wraps blocking JPA in boundedElastic scheduler
 * to stay non-blocking inside WebFlux pipeline.
 *
 * Pattern: Mono.fromCallable(() -> blockingJpaCall())
 *              .subscribeOn(Schedulers.boundedElastic())
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TourService {

    private final TourRepository tourRepository;
    private final TourMapper tourMapper;

    // ─── Create ─────────────────────────────────────────────────────────────

    @Transactional
    public Mono<TourResponse> createTour(CreateTourRequest request) {
        return Mono.fromCallable(() -> {
            String slug = generateUniqueSlug(request.getName());

            if (tourRepository.existsByNameIgnoreCase(request.getName())) {
                throw new DuplicateResourceException("A tour with this name already exists");
            }

            Tour tour = tourMapper.toEntity(request, slug);
            Tour saved = tourRepository.save(tour);
            log.info("Tour created: {} ({})", saved.getName(), saved.getId());
            return tourMapper.toResponse(saved);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Read ────────────────────────────────────────────────────────────────

    public Mono<TourResponse> getTourById(UUID id) {
        return Mono.fromCallable(() ->
                tourRepository.findByIdAndDeletedFalse(id)
                        .map(tourMapper::toResponse)
                        .orElseThrow(() -> new ResourceNotFoundException("Tour not found with id: " + id))
        ).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<TourResponse> getTourBySlug(String slug) {
        return Mono.fromCallable(() ->
                tourRepository.findBySlugAndDeletedFalse(slug)
                        .map(tourMapper::toResponse)
                        .orElseThrow(() -> new ResourceNotFoundException("Tour not found: " + slug))
        ).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Page<TourSummaryResponse>> listTours(int page, int size, TourCategory category) {
        return Mono.fromCallable(() -> {
            Pageable pageable = PageRequest.of(page, size, Sort.by("createdDate").descending());
            Page<Tour> tours = (category != null)
                    ? tourRepository.findAllByDeletedFalseAndActiveTrueAndCategory(category, pageable)
                    : tourRepository.findAllByDeletedFalseAndActiveTrue(pageable);
            return tours.map(tourMapper::toSummary);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Flux<TourSummaryResponse> getFeaturedTours() {
        return Mono.fromCallable(() ->
                tourRepository.findAllByDeletedFalseAndActiveTrueAndFeaturedTrue()
                        .stream()
                        .map(tourMapper::toSummary)
                        .toList()
        ).subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    public Mono<Page<TourSummaryResponse>> searchTours(String query, int page, int size) {
        return Mono.fromCallable(() -> {
            Pageable pageable = PageRequest.of(page, size, Sort.by("averageRating").descending());
            return tourRepository.searchTours(query.trim(), pageable)
                    .map(tourMapper::toSummary);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Update ──────────────────────────────────────────────────────────────

    @Transactional
    public Mono<TourResponse> updateTour(UUID id, UpdateTourRequest request) {
        return Mono.fromCallable(() -> {
            Tour tour = tourRepository.findByIdAndDeletedFalse(id)
                    .orElseThrow(() -> new ResourceNotFoundException("Tour not found: " + id));

            tourMapper.applyUpdate(tour, request);
            Tour saved = tourRepository.save(tour);
            log.info("Tour updated: {} ({})", saved.getName(), saved.getId());
            return tourMapper.toResponse(saved);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Delete (soft) ───────────────────────────────────────────────────────

    @Transactional
    public Mono<Void> deleteTour(UUID id) {
        return Mono.fromCallable(() -> {
            Tour tour = tourRepository.findByIdAndDeletedFalse(id)
                    .orElseThrow(() -> new ResourceNotFoundException("Tour not found: " + id));
            tour.setDeleted(true);
            tour.setActive(false);
            tourRepository.save(tour);
            log.info("Tour soft-deleted: {} ({})", tour.getName(), tour.getId());
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // ─── Admin stats ─────────────────────────────────────────────────────────

    public Mono<Long> countActiveTours() {
        return Mono.fromCallable(tourRepository::countActiveTours)
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Slug generation ─────────────────────────────────────────────────────

    private String generateUniqueSlug(String name) {
        String base = slugify(name);
        if (!tourRepository.existsBySlug(base)) return base;

        // Append incrementing suffix until unique
        int suffix = 2;
        String candidate = base + "-" + suffix;
        while (tourRepository.existsBySlug(candidate)) {
            candidate = base + "-" + (++suffix);
        }
        return candidate;
    }

    private static final Pattern NON_ALPHANUMERIC = Pattern.compile("[^a-z0-9]+");

    private String slugify(String input) {
        String normalized = Normalizer.normalize(input.toLowerCase().trim(), Normalizer.Form.NFD);
        return NON_ALPHANUMERIC.matcher(normalized).replaceAll("-")
                .replaceAll("^-|-$", "");
    }
}
