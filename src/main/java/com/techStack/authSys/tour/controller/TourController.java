package com.techStack.authSys.tour.controller;

import com.techStack.authSys.tour.dto.request.CreateTourRequest;
import com.techStack.authSys.tour.dto.request.UpdateTourRequest;
import com.techStack.authSys.tour.dto.response.TourResponse;
import com.techStack.authSys.tour.dto.response.TourSummaryResponse;
import com.techStack.authSys.tour.models.TourCategory;
import com.techStack.authSys.tour.services.TourService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Tour endpoints for Damuchi Safaris.
 *
 * Public:
 *   GET  /api/tours               — paginated list, optional category/country/destination filters
 *   GET  /api/tours/featured      — homepage featured tours
 *   GET  /api/tours/search        — search by keyword
 *   GET  /api/tours/{slug}        — tour detail page
 *
 * Admin/Manager only:
 *   POST   /api/tours             — create tour
 *   PUT    /api/tours/{id}        — update tour
 *   DELETE /api/tours/{id}        — soft delete tour
 *
 * NOTE: Spring 6 / Boot 3 disabled trailing-slash matching by default, so
 * "/api/tours" and "/api/tours/" are now two distinct routes rather than
 * aliases. Every mapping below is written WITHOUT a trailing slash to match
 * exactly what the frontend calls — don't add "/" back to any of these, and
 * don't add a second overload of any of these methods with a "/" variant;
 * that's exactly what caused the 405 and the silently-ignored
 * country/destination filters.
 */
@Slf4j
@RestController
@RequestMapping("/api/tours")
@RequiredArgsConstructor
@Tag(name = "Tours", description = "Damuchi Safaris tour management")
public class TourController {

    private final TourService tourService;

    // ─── Public endpoints ────────────────────────────────────────────────────

    @GetMapping
    @Operation(summary = "List active tours with optional category/country/destination filters")
    public Mono<Page<TourSummaryResponse>> listTours(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) TourCategory category,
            @RequestParam(required = false) String country,
            @RequestParam(required = false) String destination
    ) {
        return tourService.listTours(page, size, category, country, destination);
    }

    @GetMapping("/featured")
    @Operation(summary = "Get featured tours for homepage")
    public Flux<TourSummaryResponse> getFeaturedTours() {
        return tourService.getFeaturedTours();
    }

    @GetMapping("/search")
    @Operation(summary = "Search tours by keyword")
    public Mono<Page<TourSummaryResponse>> searchTours(
            @RequestParam @Parameter(description = "Search keyword") String q,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "12") int size
    ) {
        return tourService.searchTours(q, page, size);
    }

    @GetMapping("/{slug}")
    @Operation(summary = "Get tour detail by slug")
    public Mono<TourResponse> getTourBySlug(@PathVariable String slug) {
        return tourService.getTourBySlug(slug);
    }

    @GetMapping("/id/{id}")
    @Operation(summary = "Get tour detail by ID — used by admin/staff tooling")
    public Mono<TourResponse> getTourById(@PathVariable UUID id) {
        return tourService.getTourById(id);
    }

    // ─── Admin / Manager endpoints ───────────────────────────────────────────

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN', 'MANAGER')")
    @Operation(summary = "Create a new tour — Admin/Manager only")
    public Mono<TourResponse> createTour(@Valid @RequestBody CreateTourRequest request) {
        log.info("Creating tour: {}", request.name());
        return tourService.createTour(request);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN', 'MANAGER')")
    @Operation(summary = "Update a tour — Admin/Manager only")
    public Mono<TourResponse> updateTour(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateTourRequest request
    ) {
        return tourService.updateTour(id, request);
    }

    @PatchMapping("/{id}/publish")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN', 'MANAGER')")
    @Operation(summary = "Publish a tour, making it visible and bookable by customers — Admin/Manager only")
    public Mono<TourResponse> publishTour(@PathVariable UUID id) {
        log.info("Publishing tour: {}", id);
        return tourService.publishTour(id);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Soft delete a tour — Admin only")
    public Mono<Void> deleteTour(@PathVariable UUID id) {
        log.info("Deleting tour: {}", id);
        return tourService.deleteTour(id);
    }

    @GetMapping("/admin/stats/count")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN', 'MANAGER')")
    @Operation(summary = "Count of active tours")
    public Mono<Long> countActiveTours() {
        return tourService.countActiveTours();
    }
}