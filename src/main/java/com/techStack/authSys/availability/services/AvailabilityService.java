package com.techStack.authSys.availability.services;

import com.techStack.authSys.availability.dto.request.BulkCreateAvailabilityRequest;
import com.techStack.authSys.availability.dto.request.CreateAvailabilityRequest;
import com.techStack.authSys.availability.dto.request.UpdateAvailabilityRequest;
import com.techStack.authSys.availability.dto.response.AvailabilityResponse;
import com.techStack.authSys.availability.dto.response.AvailabilitySummaryResponse;
import com.techStack.authSys.availability.dto.response.BulkCreateResult;
import com.techStack.authSys.availability.models.AvailabilityStatus;
import com.techStack.authSys.availability.models.TourAvailability;
import com.techStack.authSys.availability.repository.TourAvailabilityRepository;
import com.techStack.authSys.common.exception.DuplicateResourceException;
import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.repository.TourRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * AvailabilityService
 *
 * Manages the full lifecycle of TourAvailability slots:
 *
 *   CREATE  → single slot or bulk date-range
 *   READ    → public calendar (OPEN only), staff full list, date-range
 *   UPDATE  → adjust slots, price override, deadline, notes
 *   CLOSE   → OPEN/FULL → CLOSED (blocks booking without deleting)
 *   REOPEN  → CLOSED → OPEN (if slots remain)
 *   DELETE  → soft-delete (sets deleted = true)
 *
 * Threading: all JPA calls wrapped in Mono.fromCallable().subscribeOn(boundedElastic())
 * matching the pattern in TourService and BookingService.
 *
 * Note: reserveSlots() and releaseSlots() are NOT called here.
 * Those are BookingService's responsibility — this service only manages
 * the slot definition, not the booking transaction.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AvailabilityService {

    private final TourAvailabilityRepository availabilityRepository;
    private final TourRepository             tourRepository;

    // ── CREATE ────────────────────────────────────────────────────────────────

    /**
     * Create a single availability slot for a enquire-button.tsx date.
     * Validates: enquire-button.tsx exists and is active, date is in the future,
     * no duplicate slot for this enquire-button.tsx + date.
     */
    @Transactional
    public Mono<AvailabilityResponse> createSlot(CreateAvailabilityRequest req) {
        return Mono.fromCallable(() -> {

            Tour tour = loadActiveTour(req.tourId());

            if (req.date().isBefore(LocalDate.now())) {
                throw new IllegalArgumentException("Slot date must be in the future");
            }
            if (availabilityRepository.existsByTourIdAndDate(tour.getId(), req.date())) {
                throw new DuplicateResourceException(
                        HttpStatus.CONFLICT,"A slot already exists for enquire-button.tsx " + tour.getName()
                        + " on " + req.date());
            }

            // availableSlots defaults to maxSlots if not provided
            int available = req.availableSlots() != null
                    ? req.availableSlots()
                    : req.maxSlots();

            if (available > req.maxSlots()) {
                throw new IllegalArgumentException(
                        "availableSlots (" + available + ") cannot exceed maxSlots (" + req.maxSlots() + ")");
            }

            // returnDate isn't on CreateAvailabilityRequest yet — defaulted from
            // enquire-button.tsx duration until the DTO exposes an explicit override field.
            LocalDate returnDate = req.date().plusDays(Math.max(0, tour.getDurationDays() - 1));

            TourAvailability slot = TourAvailability.builder()
                    .tour(tour)
                    .date(req.date())
                    .returnDate(returnDate)
                    .maxSlots(req.maxSlots())
                    .availableSlots(available)
                    .status(available == 0 ? AvailabilityStatus.FULL : AvailabilityStatus.OPEN)
                    .bookingDeadline(req.bookingDeadline())
                    .priceOverride(req.priceOverride())
                    .internalNotes(req.internalNotes())
                    .build();

            TourAvailability saved = availabilityRepository.save(slot);
            log.info("Slot created: enquire-button.tsx={} date={} slots={}",
                    tour.getName(), req.date(), req.maxSlots());

            return toResponse(saved);

        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Bulk-create slots across a date range, optionally filtered to specific
     * days of the week (e.g. every Saturday in December).
     *
     * Dates already having a slot, or dates in the past, are silently skipped.
     * Returns a BulkCreateResult summarising created vs skipped counts.
     */
    @Transactional
    public Mono<BulkCreateResult> bulkCreateSlots(BulkCreateAvailabilityRequest req) {
        return Mono.fromCallable(() -> {

            if (req.to().isBefore(req.from())) {
                throw new IllegalArgumentException("'to' date must be on or after 'from' date");
            }

            Tour tour = loadActiveTour(req.tourId());

            List<LocalDate> candidates = req.from()
                    .datesUntil(req.to().plusDays(1))
                    .filter(d -> !d.isBefore(LocalDate.now()))
                    .filter(d -> req.daysOfWeek() == null
                            || req.daysOfWeek().isEmpty()
                            || req.daysOfWeek().contains(d.getDayOfWeek()))
                    .toList();

            List<AvailabilityResponse> created = new ArrayList<>();
            List<String>               skipped = new ArrayList<>();

            for (LocalDate date : candidates) {
                if (availabilityRepository.existsByTourIdAndDate(tour.getId(), date)) {
                    skipped.add(date.toString());
                    continue;
                }

                // Compute booking deadline relative to each date if an offset is provided
                OffsetDateTime deadline = req.bookingDeadlineOffset() != null
                        ? date.atTime(req.bookingDeadlineOffset().toLocalTime())
                        .atOffset(ZoneOffset.UTC)
                        : null;

                LocalDate returnDate = date.plusDays(Math.max(0, tour.getDurationDays() - 1));

                TourAvailability slot = TourAvailability.builder()
                        .tour(tour)
                        .date(date)
                        .returnDate(returnDate)
                        .maxSlots(req.maxSlots())
                        .availableSlots(req.maxSlots())
                        .status(AvailabilityStatus.OPEN)
                        .bookingDeadline(deadline)
                        .priceOverride(req.priceOverride())
                        .internalNotes(req.internalNotes())
                        .build();

                created.add(toResponse(availabilityRepository.save(slot)));
            }

            log.info("Bulk slots: enquire-button.tsx={} range={}/{} created={} skipped={}",
                    tour.getName(), req.from(), req.to(), created.size(), skipped.size());

            return BulkCreateResult.builder()
                    .created(created.size())
                    .skipped(skipped.size())
                    .total(candidates.size() + skipped.size())
                    .createdSlots(created)
                    .skippedDates(skipped)
                    .build();

        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── READ ──────────────────────────────────────────────────────────────────

    /**
     * Public booking calendar — OPEN slots from today forward.
     * Customer-facing: returns lightweight AvailabilitySummaryResponse.
     */
    public Flux<AvailabilitySummaryResponse> getUpcomingOpenSlots(UUID tourId) {
        return Mono.fromCallable(() ->
                        availabilityRepository
                                .findUpcomingByTour(tourId, LocalDate.now())
                                .stream()
                                .filter(s -> s.getStatus() == AvailabilityStatus.OPEN)
                                .map(this::toSummary)
                                .toList()
                ).subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /**
     * Staff calendar view — all non-deleted slots in a date range.
     * Returns full AvailabilityResponse including internal notes and occupancy.
     */
    public Flux<AvailabilityResponse> getCalendar(UUID tourId, LocalDate from, LocalDate to) {
        return Mono.fromCallable(() ->
                        availabilityRepository
                                .findByTourIdAndDateBetweenOrderByDateAsc(tourId, from, to)
                                .stream()
                                .map(this::toResponse)
                                .toList()
                ).subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /**
     * All non-deleted slots for a enquire-button.tsx — staff management list.
     */
    public Flux<AvailabilityResponse> getAllForTour(UUID tourId) {
        return Mono.fromCallable(() ->
                        availabilityRepository
                                .findByTourIdAndDeletedFalseOrderByDateAsc(tourId)
                                .stream()
                                .map(this::toResponse)
                                .toList()
                ).subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /**
     * Single slot by ID — staff detail view.
     */
    public Mono<AvailabilityResponse> getSlotById(UUID id) {
        return Mono.fromCallable(() ->
                availabilityRepository
                        .findByIdAndDeletedFalse(id)
                        .map(this::toResponse)
                        .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Availability slot not found: " + id))
        ).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Count of upcoming open slots for a enquire-button.tsx — admin dashboard stat.
     */
    public Mono<Long> countUpcomingOpenSlots(UUID tourId) {
        return Mono.fromCallable(() ->
                availabilityRepository.countUpcomingOpenSlots(tourId)
        ).subscribeOn(Schedulers.boundedElastic());
    }

    // ── UPDATE ────────────────────────────────────────────────────────────────

    /**
     * Patch a slot — only non-null fields are applied.
     * maxSlots and date are immutable (delete and recreate to change).
     * If availableSlots is updated, status is recalculated automatically.
     */
    @Transactional
    public Mono<AvailabilityResponse> updateSlot(UUID id, UpdateAvailabilityRequest req) {
        return Mono.fromCallable(() -> {

            TourAvailability slot = loadSlot(id);

            if (req.availableSlots() != null) {
                if (req.availableSlots() > slot.getMaxSlots()) {
                    throw new IllegalArgumentException(
                            "availableSlots (" + req.availableSlots()
                                    + ") cannot exceed maxSlots (" + slot.getMaxSlots() + ")");
                }
                slot.setAvailableSlots(req.availableSlots());
                // Recalculate status based on new available count
                if (req.availableSlots() == 0 && slot.getStatus() == AvailabilityStatus.OPEN) {
                    slot.setStatus(AvailabilityStatus.FULL);
                } else if (req.availableSlots() > 0 && slot.getStatus() == AvailabilityStatus.FULL) {
                    slot.setStatus(AvailabilityStatus.OPEN);
                }
            }
            if (req.bookingDeadline() != null) slot.setBookingDeadline(req.bookingDeadline());
            if (req.priceOverride()    != null) slot.setPriceOverride(req.priceOverride());
            if (req.internalNotes()    != null) slot.setInternalNotes(req.internalNotes());
            // TODO: once UpdateAvailabilityRequest exposes a currency field,
            // apply it here — only meaningful alongside priceOverride.

            TourAvailability saved = availabilityRepository.save(slot);
            log.info("Slot updated: id={} date={}", id, saved.getDate());
            return toResponse(saved);

        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── CLOSE / REOPEN ────────────────────────────────────────────────────────

    /**
     * Close a slot — status → CLOSED. Blocks booking without deleting history.
     * Callable by MANAGER or above.
     */
    @Transactional
    public Mono<AvailabilityResponse> closeSlot(UUID id) {
        return Mono.fromCallable(() -> {
            TourAvailability slot = loadSlot(id);
            if (slot.getStatus() == AvailabilityStatus.CANCELLED) {
                throw new IllegalStateException("Cannot close a CANCELLED slot");
            }
            slot.close();
            TourAvailability saved = availabilityRepository.save(slot);
            log.info("Slot closed: id={} date={}", id, saved.getDate());
            return toResponse(saved);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Reopen a CLOSED slot — status → OPEN (if available slots > 0).
     */
    @Transactional
    public Mono<AvailabilityResponse> reopenSlot(UUID id) {
        return Mono.fromCallable(() -> {
            TourAvailability slot = loadSlot(id);
            if (slot.getStatus() != AvailabilityStatus.CLOSED) {
                throw new IllegalStateException(
                        "Only CLOSED slots can be reopened. Current status: " + slot.getStatus());
            }
            slot.reopen();
            TourAvailability saved = availabilityRepository.save(slot);
            log.info("Slot reopened: id={} date={} availableSlots={}",
                    id, saved.getDate(), saved.getAvailableSlots());
            return toResponse(saved);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // ── DELETE ────────────────────────────────────────────────────────────────

    /**
     * Soft-delete a slot. Only safe if no confirmed bookings exist on it.
     * Hard guard should be added in Phase 2: check bookingRepository.existsByAvailabilityId().
     */
    @Transactional
    public Mono<Void> deleteSlot(UUID id) {
        return Mono.fromCallable(() -> {
            TourAvailability slot = loadSlot(id);
            slot.setDeleted(true);
            availabilityRepository.save(slot);
            log.warn("Slot soft-deleted: id={} date={} enquire-button.tsx={}",
                    id, slot.getDate(), slot.getTour().getName());
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private Tour loadActiveTour(UUID tourId) {
        Tour tour = tourRepository.findByIdAndDeletedFalse(tourId)
                .orElseThrow(() -> new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Tour not found: " + tourId));
        if (!Boolean.TRUE.equals(tour.getActive())) {
            throw new IllegalArgumentException(
                    "Cannot create slots for an inactive enquire-button.tsx: " + tour.getName()
            );
        }
        return tour;
    }

    private TourAvailability loadSlot(UUID id) {
        return availabilityRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "Availability slot not found: " + id));
    }

    // ── Mappers ───────────────────────────────────────────────────────────────

    private AvailabilityResponse toResponse(TourAvailability slot) {
        return AvailabilityResponse.builder()
                .id(slot.getId())
                .tourId(slot.getTour().getId())
                .tourName(slot.getTour().getName())
                .tourSlug(slot.getTour().getSlug())
                .date(slot.getDate())
                .maxSlots(slot.getMaxSlots())
                .availableSlots(slot.getAvailableSlots())
                .bookedCount(slot.getBookedCount())
                .occupancyPercent(slot.getOccupancyPercent())
                .status(slot.getStatus())
                .statusDescription(slot.getStatus().getDescription())
                .tourBasePrice(slot.getTour().getPrice())
                .priceOverride(slot.getPriceOverride())
                .effectivePrice(slot.getEffectivePrice())
                .bookingDeadline(slot.getBookingDeadline())
                .internalNotes(slot.getInternalNotes())
                .createdDate(slot.getCreatedDate() != null
                        ? slot.getCreatedDate().atOffset(ZoneOffset.UTC) : null)
                .lastModifiedDate(slot.getLastModifiedDate() != null
                        ? slot.getLastModifiedDate().atOffset(ZoneOffset.UTC) : null)
                .build();
    }

    private AvailabilitySummaryResponse toSummary(TourAvailability slot) {
        return AvailabilitySummaryResponse.builder()
                .id(slot.getId())
                .date(slot.getDate())
                .availableSlots(slot.getAvailableSlots())
                .status(slot.getStatus())
                .effectivePrice(slot.getEffectivePrice())
                .bookingDeadline(slot.getBookingDeadline())
                .build();
    }
}