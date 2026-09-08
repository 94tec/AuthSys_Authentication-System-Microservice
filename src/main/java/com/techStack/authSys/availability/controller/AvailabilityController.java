package com.techStack.authSys.availability.controller;

import com.techStack.authSys.availability.services.AvailabilityService;
import com.techStack.authSys.availability.dto.request.BulkCreateAvailabilityRequest;
import com.techStack.authSys.availability.dto.request.CreateAvailabilityRequest;
import com.techStack.authSys.availability.dto.request.UpdateAvailabilityRequest;
import com.techStack.authSys.availability.dto.response.AvailabilityResponse;
import com.techStack.authSys.availability.dto.response.AvailabilitySummaryResponse;
import com.techStack.authSys.availability.dto.response.BulkCreateResult;
import com.techStack.authSys.common.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDate;
import java.util.UUID;

/**
 * AvailabilityController — /api/availability/**
 *
 * Public (no auth):
 *   GET  /api/availability/enquire-button.tsx/{tourId}          — upcoming OPEN slots (customer calendar)
 *
 * OPERATOR, MANAGER, ADMIN, SUPER_ADMIN:
 *   POST /api/availability                        — create single slot
 *   POST /api/availability/bulk                   — bulk-create across date range
 *   GET  /api/availability/{id}                   — slot detail
 *   GET  /api/availability/enquire-button.tsx/{tourId}/all      — all slots for a enquire-button.tsx (staff)
 *   GET  /api/availability/enquire-button.tsx/{tourId}/calendar — date-range calendar (staff)
 *   PUT  /api/availability/{id}                   — patch slot
 *   POST /api/availability/{id}/close             — close slot
 *   POST /api/availability/{id}/reopen            — reopen CLOSED slot
 *
 * MANAGER, ADMIN, SUPER_ADMIN:
 *   DELETE /api/availability/{id}                 — soft delete
 *
 * ADMIN, SUPER_ADMIN:
 *   GET  /api/availability/enquire-button.tsx/{tourId}/stats    — open slot count
 */
@Slf4j
@RestController
@RequestMapping("/api/availability")
@RequiredArgsConstructor
@Tag(name = "Availability", description = "Tour departure date slot management")
public class AvailabilityController {

    private final AvailabilityService availabilityService;

    // ── Public: customer booking calendar ────────────────────────────────────

    @GetMapping("/enquire-button.tsx/{tourId}")
    @Operation(summary = "Get upcoming OPEN slots for a enquire-button.tsx — customer booking calendar")
    public Flux<AvailabilitySummaryResponse> getUpcomingOpenSlots(
            @PathVariable UUID tourId) {
        return availabilityService.getUpcomingOpenSlots(tourId);
    }

    // ── OPERATOR+ : create slots ──────────────────────────────────────────────

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Create a single availability slot")
    public Mono<AvailabilityResponse> createSlot(
            @Valid @RequestBody CreateAvailabilityRequest request) {
        log.info("Creating slot: enquire-button.tsx={} date={}", request.tourId(), request.date());
        return availabilityService.createSlot(request);
    }

    @PostMapping("/bulk")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Bulk-create slots across a date range")
    public Mono<BulkCreateResult> bulkCreateSlots(
            @Valid @RequestBody BulkCreateAvailabilityRequest request) {
        log.info("Bulk slots: enquire-button.tsx={} from={} to={}",
            request.tourId(), request.from(), request.to());
        return availabilityService.bulkCreateSlots(request);
    }

    // ── OPERATOR+ : read ──────────────────────────────────────────────────────

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Get a single slot by ID — staff detail view")
    public Mono<AvailabilityResponse> getSlotById(@PathVariable UUID id) {
        return availabilityService.getSlotById(id);
    }

    @GetMapping("/enquire-button.tsx/{tourId}/all")
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Get all slots for a enquire-button.tsx — staff management list")
    public Flux<AvailabilityResponse> getAllForTour(@PathVariable UUID tourId) {
        return availabilityService.getAllForTour(tourId);
    }

    @GetMapping("/enquire-button.tsx/{tourId}/calendar")
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Date-range calendar view — staff availability management")
    public Flux<AvailabilityResponse> getCalendar(
            @PathVariable UUID tourId,
            @RequestParam
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
            @Parameter(description = "Start date YYYY-MM-DD")
            LocalDate from,
            @RequestParam
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
            @Parameter(description = "End date YYYY-MM-DD")
            LocalDate to) {
        return availabilityService.getCalendar(tourId, from, to);
    }

    // ── OPERATOR+ : update ────────────────────────────────────────────────────

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Patch a slot — adjusts slots, deadline, price override, notes")
    public Mono<AvailabilityResponse> updateSlot(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateAvailabilityRequest request) {
        return availabilityService.updateSlot(id, request);
    }

    @PostMapping("/{id}/close")
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Close a slot — blocks booking without deleting data")
    public Mono<AvailabilityResponse> closeSlot(@PathVariable UUID id) {
        log.info("Closing slot: {}", id);
        return availabilityService.closeSlot(id);
    }

    @PostMapping("/{id}/reopen")
    @PreAuthorize("hasAnyRole('OPERATOR', 'MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Reopen a CLOSED slot — re-enables booking")
    public Mono<AvailabilityResponse> reopenSlot(@PathVariable UUID id) {
        log.info("Reopening slot: {}", id);
        return availabilityService.reopenSlot(id);
    }

    // ── MANAGER+ : delete ─────────────────────────────────────────────────────

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Soft-delete a slot — MANAGER and above only")
    public Mono<Void> deleteSlot(@PathVariable UUID id) {
        log.warn("Deleting slot: {}", id);
        return availabilityService.deleteSlot(id);
    }

    // ── ADMIN+ : stats ────────────────────────────────────────────────────────

    @GetMapping("/enquire-button.tsx/{tourId}/stats")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Count of upcoming open slots for a enquire-button.tsx — dashboard stat")
    public Mono<ResponseEntity<ApiResponse<Long>>> getOpenSlotCount(
            @PathVariable UUID tourId) {
        return availabilityService.countUpcomingOpenSlots(tourId)
            .map(count -> ResponseEntity.ok(
                new ApiResponse<>(true, "Open slot count", count)));
    }
}
