package com.techStack.authSys.tour.services;

import com.techStack.authSys.common.exception.DuplicateResourceException;
import com.techStack.authSys.common.exception.ResourceNotFoundException;
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
import org.hibernate.Hibernate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.text.Normalizer;
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
    private final TransactionTemplate transactionTemplate;

    // ─── Create ─────────────────────────────────────────────────────────────

    @Transactional
    public Mono<TourResponse> createTour(CreateTourRequest request) {
        return Mono.fromCallable(() -> {
            // Check duplicate BEFORE doing the work of generating a slug —
            // no point slugifying a name we're about to reject.
            if (tourRepository.existsByNameIgnoreCase(request.name())) {
                throw new DuplicateResourceException(HttpStatus.CONFLICT, "A tour with this name already exists");
            }

            String slug = generateUniqueSlug(request.name());
            Tour tour = tourMapper.toEntity(request, slug);
            Tour saved = tourRepository.save(tour);
            log.info("Tour created: {} ({})", saved.getName(), saved.getId());
            return tourMapper.toResponse(saved);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Read ────────────────────────────────────────────────────────────────

    // TourService.java
    public Mono<TourResponse> getTourById(UUID id) {
        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    Tour tour = tourRepository.findByIdAndDeletedFalse(id)
                            .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Tour not found: " + id));

                    // Force each bag to load individually while the transaction
                    // (and session) from transactionTemplate is still open.
                    // BatchSize(25) on each collection means Hibernate issues one
                    // small batched SELECT per collection here, not N+1 — six
                    // total queries, each cheap, rather than one fetch-joined
                    // query (which MultipleBagFetchException rules out anyway
                    // since these are all Lists, not Sets).
                    tour.getHighlights().size();
                    tour.getItinerary().size();
                    tour.getInclusions().size();
                    tour.getExclusions().size();
                    tour.getRequirements().size();
                    tour.getGalleryImages().size();

                    return tourMapper.toResponse(tour);
                }))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<TourResponse> getTourBySlug(String slug) {
        return Mono.fromCallable(() ->
                tourRepository.findBySlugAndDeletedFalse(slug)
                        .map(tourMapper::toResponse)
                        .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Tour not found: " + slug))
        ).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Unified catalogue listing. Every filter is optional and independent:
     *  - category: theme filter (WILDLIFE, LUXURY, ...) — used by /experiences/* pages
     *  - country: exact-match, case-insensitive — used by /safaris/{country} and
     *    /destinations/{country} pages, replacing the old "search for the country
     *    name and hope it matches" approach
     *  - destination: exact-match, case-insensitive — used by specific-place pages
     *    like /destinations/maasai-mara
     *
     * Pass null for any filter you don't want applied. See
     * TourRepository#findFiltered for the underlying query.
     */
    public Mono<Page<TourSummaryResponse>> listTours(
            int page,
            int size,
            TourCategory category,
            String country,
            String destination
    ) {
        return Mono.fromCallable(() -> {
            Pageable pageable = PageRequest.of(page, size, Sort.by("createdDate").descending());

            Page<Tour> tours = tourRepository.findFiltered(
                    category,
                    normalize(country),
                    normalize(destination),
                    pageable
            );

            return tours.map(tourMapper::toSummary);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /** Back-compat overload for existing call sites that only ever filtered by category. */
    public Mono<Page<TourSummaryResponse>> listTours(int page, int size, TourCategory category) {
        return listTours(page, size, category, null, null);
    }

    public Mono<Page<TourSummaryResponse>> searchTours(String query, int page, int size) {
        return Mono.fromCallable(() -> {
            Pageable pageable = PageRequest.of(page, size, Sort.by("averageRating").descending());
            return tourRepository.searchTours(query.trim(), pageable)
                    .map(tourMapper::toSummary);
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

    // ─── Update ──────────────────────────────────────────────────────────────

    @Transactional
    public Mono<TourResponse> updateTour(UUID id, UpdateTourRequest request) {
        return Mono.fromCallable(() -> {
            Tour tour = tourRepository.findByIdAndDeletedFalse(id)
                    .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Tour not found: " + id));

            tourMapper.applyUpdate(tour, request);
            Tour saved = tourRepository.save(tour);
            log.info("Tour updated: {} ({})", saved.getName(), saved.getId());
            return tourMapper.toResponse(saved);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<TourResponse> publishTour(UUID id) {
        return Mono.fromCallable(() ->
                transactionTemplate.execute(status -> {
                    Tour tour = tourRepository.findDetailedByIdAndDeletedFalse(id)
                            .orElseThrow(() -> new ResourceNotFoundException(
                                    HttpStatus.NOT_FOUND, "Tour not found: " + id));

                    if (Boolean.TRUE.equals(tour.getActive())) {
                        log.info("Tour already published, skipping: {} ({})", tour.getName(), tour.getId());
                        return tourMapper.to_Response(tour);
                    }

                    tour.setActive(true);
                    Tour saved = tourRepository.save(tour);
                    log.info("Tour published: {} ({})", saved.getName(), saved.getId());
                    return tourMapper.to_Response(saved);
                })
        ).subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Delete (soft) ───────────────────────────────────────────────────────

    @Transactional
    public Mono<Void> deleteTour(UUID id) {
        return Mono.fromCallable(() -> {
            Tour tour = tourRepository.findByIdAndDeletedFalse(id)
                    .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Tour not found: " + id));
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

    /** Total non-deleted tours, active or not — for admin dashboard totals. */
    public Mono<Long> countAllTours() {
        return Mono.fromCallable(tourRepository::countByDeletedFalse)
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /** Blank strings are treated the same as absent filters. */
    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim() : null;
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