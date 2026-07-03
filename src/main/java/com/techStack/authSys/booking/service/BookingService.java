package com.techStack.authSys.booking.service;

import com.techStack.authSys.booking.dto.request.CreateBookingRequest;
import com.techStack.authSys.booking.dto.response.BookingDTO;
import com.techStack.authSys.booking.mapper.BookingMapper;
import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.models.BookingStatus;
import com.techStack.authSys.booking.models.BookingTraveler;
import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.tour.models.AvailabilityStatus;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourAvailability;
import com.techStack.authSys.tour.repositories.TourAvailabilityRepository;
import com.techStack.authSys.tour.repository.TourRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Booking Service
 *
 * Handles the full booking lifecycle:
 *   CREATE  → validate → reserve slots (optimistic lock) → persist
 *   READ    → customer's own bookings, staff all-bookings
 *   CANCEL  → release slots → soft-delete booking
 *   CONFIRM → mark paid (staff/payment webhook)
 *   COMPLETE → mark completed (post-tour)
 *
 * Threading: all JPA/blocking work runs on Schedulers.boundedElastic()
 * wrapped in Mono.fromCallable(), matching the pattern used in TourService.
 *
 * Optimistic locking: TourAvailability.@Version means concurrent booking
 * attempts throw OptimisticLockingFailureException — caught here and
 * converted to HTTP 409 CONFLICT with a user-friendly message.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BookingService {

    private final BookingRepository          bookingRepository;
    private final TourRepository             tourRepository;
    private final TourAvailabilityRepository availabilityRepository;
    private final BookingMapper              bookingMapper;

    // ── CREATE ───────────────────────────────────────────────────────────────

    /**
     * Create a booking for an authenticated USER.
     *
     * Steps:
     *   1. Load tour (must be active, not deleted)
     *   2. Load availability slot (must be OPEN, not past booking deadline)
     *   3. Validate slot belongs to tour
     *   4. Check capacity via hasAvailability()
     *   5. Prevent duplicate active booking (same customer, same slot)
     *   6. Snapshot pricing at booking time
     *   7. Build booking + travelers
     *   8. reserveSlots() on the availability (mutates availableSlots + status)
     *   9. Save availability (triggers optimistic lock check)
     *  10. Save booking
     *  11. Increment tour.totalBookings counter
     *  12. Return DTO
     *
     * @param customerId    Firebase UID of the authenticated customer
     * @param customerEmail email from the authenticated principal
     * @param customerName  display name from the authenticated principal
     * @param req           validated booking request
     */
    @Transactional
    public Mono<BookingDTO> createBooking(
            String customerId,
            String customerEmail,
            String customerName,
            CreateBookingRequest req) {

        return Mono.fromCallable(() -> {

                    // 1. Load tour
                    Tour tour = tourRepository
                            .findByIdAndDeletedFalse(req.tourId())
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND,
                                    "Tour not found or no longer available"));

                    if (!tour.isActive()) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "This tour is not currently bookable");
                    }

                    // 2. Load availability slot
                    TourAvailability slot = availabilityRepository
                            .findById(req.availabilityId())
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND,
                                    "Availability slot not found"));

                    // 3. Validate slot belongs to requested tour
                    if (!slot.getTour().getId().equals(tour.getId())) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Availability slot does not belong to this tour");
                    }

                    // 4. Slot must be OPEN
                    if (slot.getStatus() != AvailabilityStatus.OPEN) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "This tour date is no longer available ("
                                        + slot.getStatus().name() + ")");
                    }

                    // 5. Past booking deadline check
                    if (slot.getBookingDeadline() != null
                            && OffsetDateTime.now().isAfter(slot.getBookingDeadline())) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Booking deadline for this date has passed");
                    }

                    // 6. Past tour date check
                    if (slot.getDate().isBefore(LocalDate.now())) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Cannot book a tour date in the past");
                    }

                    // 7. Capacity check via TourAvailability.hasAvailability()
                    if (!slot.hasAvailability(req.travelerCount())) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "Not enough slots available. Requested: "
                                        + req.travelerCount()
                                        + ", Available: "
                                        + slot.getAvailableSlots());
                    }

                    // 8. Prevent duplicate active booking (same customer, same slot)
                    long existing = bookingRepository
                            .countActiveBookingForCustomerOnSlot(
                                    slot.getId(), customerId);
                    if (existing > 0) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "You already have an active booking for this tour date");
                    }

                    // 9. Validate traveler list matches travelerCount
                    if (req.travelers() == null
                            || req.travelers().size() != req.travelerCount()) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Traveler list size must match travelerCount. "
                                        + "Expected: " + req.travelerCount()
                                        + ", Got: "
                                        + (req.travelers() == null ? 0 : req.travelers().size()));
                    }

                    // 10. Snapshot pricing at booking time
                    // Price is frozen here — later changes to tour.pricePerPerson
                    // do NOT affect confirmed bookings.
                    BigDecimal pricePerTraveler = tour.getPricePerPerson();
                    BigDecimal totalPrice = pricePerTraveler
                            .multiply(BigDecimal.valueOf(req.travelerCount()));

                    // 11. Build booking
                    Booking booking = Booking.builder()
                            .customerId(customerId)
                            .customerEmail(customerEmail)
                            .customerName(customerName)
                            .tour(tour)
                            .availability(slot)
                            .tourDate(slot.getDate())
                            .tourName(tour.getName())
                            .travelerCount(req.travelerCount())
                            .pricePerTraveler(pricePerTraveler)
                            .totalPrice(totalPrice)
                            .currency("KES")
                            .status(BookingStatus.PENDING_PAYMENT)
                            .specialRequests(req.specialRequests())
                            .build();

                    // 12. Add travelers — first is always lead
                    for (int i = 0; i < req.travelers().size(); i++) {
                        CreateBookingRequest.TravelerRequest t = req.travelers().get(i);
                        booking.addTraveler(BookingTraveler.builder()
                                .fullName(t.fullName())
                                .dateOfBirth(t.dateOfBirth())
                                .passportNumber(t.passportNumber())
                                .nationality(t.nationality())
                                .dietaryNotes(t.dietaryNotes())
                                .leadTraveler(i == 0)
                                .build());
                    }

                    // 13. Reserve slots — mutates availableSlots and status on the entity.
                    // TourAvailability.reserveSlots() throws IllegalStateException if
                    // insufficient — caught below as a fallback (primary guard is step 7).
                    slot.reserveSlots(req.travelerCount());

                    // 14. Save availability first — this is where optimistic lock fires
                    // if another request reserved the last slot(s) concurrently.
                    availabilityRepository.save(slot);

                    // 15. Save booking
                    Booking saved = bookingRepository.save(booking);

                    // 16. Increment tour booking counter (best-effort — non-fatal)
                    try {
                        tourRepository.incrementBookingCount(tour.getId());
                    } catch (Exception e) {
                        log.warn("⚠️ Failed to increment booking counter for tour {}: {}",
                                tour.getId(), e.getMessage());
                    }

                    log.info("✅ Booking created: {} customer: {} tour: {} date: {} travelers: {}",
                            saved.getId(), customerId,
                            tour.getName(), slot.getDate(),
                            req.travelerCount());

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(OptimisticLockingFailureException.class, e -> {
                    // Two users booked the last slot(s) simultaneously —
                    // one wins, the other gets a clear 409.
                    log.warn("⚠️ Concurrent booking conflict for availability {}: {}",
                            req.availabilityId(), e.getMessage());
                    return Mono.error(new CustomException(HttpStatus.CONFLICT,
                            "This slot was just taken. Please select another date."));
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    // TourAvailability.reserveSlots() guard fired
                    log.warn("⚠️ Slot reservation failed: {}", e.getMessage());
                    return Mono.error(new CustomException(HttpStatus.CONFLICT, e.getMessage()));
                })
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Unexpected error creating booking: {}", e.getMessage(), e);
                    return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                            "Failed to create booking. Please try again."));
                });
    }

    // ── READ: Customer ───────────────────────────────────────────────────────

    /**
     * Returns all non-deleted bookings for the authenticated customer,
     * newest first.
     */
    public Flux<BookingDTO> getMyBookings(String customerId) {
        return Mono.fromCallable(() ->
                        bookingRepository
                                .findByCustomerIdAndDeletedFalseOrderByCreatedDateDesc(customerId)
                                .stream()
                                .map(bookingMapper::toDTO)
                                .toList()
                )
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable)
                .doOnComplete(() -> log.debug("Fetched bookings for customer: {}", customerId));
    }

    /**
     * Returns a single booking by ID, scoped to the requesting customer.
     * Prevents IDOR — a customer cannot look up another customer's booking ID.
     */
    public Mono<BookingDTO> getMyBookingById(String customerId, UUID bookingId) {
        return Mono.fromCallable(() ->
                        bookingRepository
                                .findByIdAndCustomerIdAndDeletedFalse(bookingId, customerId)
                                .map(bookingMapper::toDTO)
                                .orElseThrow(() -> new CustomException(
                                        HttpStatus.NOT_FOUND,
                                        "Booking not found"))
                )
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> Mono.error(new CustomException(
                        HttpStatus.INTERNAL_SERVER_ERROR, "Failed to fetch booking")));
    }

    /**
     * Returns only active bookings (PENDING_PAYMENT + CONFIRMED) for a customer.
     * Useful for customer dashboard — "upcoming trips".
     */
    public Flux<BookingDTO> getMyActiveBookings(String customerId) {
        return Mono.fromCallable(() ->
                        bookingRepository
                                .findByCustomerIdAndStatusInAndDeletedFalse(
                                        customerId,
                                        List.of(BookingStatus.PENDING_PAYMENT,
                                                BookingStatus.CONFIRMED))
                                .stream()
                                .map(bookingMapper::toDTO)
                                .toList()
                )
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    // ── READ: Staff ───────────────────────────────────────────────────────────

    /**
     * Returns all bookings, optionally filtered by status.
     * Accessible to MANAGER, ADMIN, SUPER_ADMIN only (enforced at controller).
     */
    public Flux<BookingDTO> getAllBookings(BookingStatus status) {
        return Mono.fromCallable(() -> {
                    List<Booking> bookings = status != null
                            ? bookingRepository
                            .findByStatusAndDeletedFalseOrderByCreatedDateDesc(status)
                            : bookingRepository.findAll()
                            .stream()
                            .filter(b -> !b.isDeleted())
                            .toList();

                    return bookings.stream().map(bookingMapper::toDTO).toList();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /**
     * Returns all bookings for a specific tour date.
     * Used by operations staff for daily tour manifests.
     */
    public Flux<BookingDTO> getBookingsByDate(LocalDate date) {
        return Mono.fromCallable(() ->
                        availabilityRepository
                                .findByDate(date)
                                .stream()
                                .flatMap(slot ->
                                        bookingRepository
                                                .findByAvailabilityIdAndDeletedFalse(slot.getId())
                                                .stream())
                                .map(bookingMapper::toDTO)
                                .toList()
                )
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /**
     * Returns all bookings for a specific tour.
     */
    public Flux<BookingDTO> getBookingsByTour(UUID tourId) {
        return Mono.fromCallable(() ->
                        bookingRepository
                                .findByTourIdAndDeletedFalseOrderByTourDateAsc(tourId)
                                .stream()
                                .map(bookingMapper::toDTO)
                                .toList()
                )
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    // ── CANCEL ───────────────────────────────────────────────────────────────

    /**
     * Customer cancels their own booking.
     *
     * Steps:
     *   1. Load booking (scoped to customer — IDOR prevention)
     *   2. Check status allows cancellation (BookingStatus.isCancellable())
     *   3. Release slots back to availability
     *   4. Cancel booking (sets status + cancelledAt + soft-delete)
     *   5. Persist both
     */
    @Transactional
    public Mono<BookingDTO> cancelMyBooking(
            String customerId, UUID bookingId, String reason) {

        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndCustomerIdAndDeletedFalse(bookingId, customerId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    if (!booking.getStatus().isCancellable()) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Cannot cancel a booking with status: "
                                        + booking.getStatus().getDescription());
                    }

                    // Release slots back to the availability slot
                    TourAvailability slot = booking.getAvailability();
                    slot.releaseSlots(booking.getTravelerCount());
                    availabilityRepository.save(slot);

                    // Cancel — sets status, cancelledAt, soft-deletes
                    booking.cancel(reason);
                    Booking saved = bookingRepository.save(booking);

                    log.info("🚫 Booking cancelled: {} customer: {} reason: {}",
                            bookingId, customerId, reason);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(OptimisticLockingFailureException.class, e ->
                        Mono.error(new CustomException(HttpStatus.CONFLICT,
                                "Booking was modified concurrently. Please try again.")))
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Error cancelling booking {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Cancellation failed. Please try again."));
                });
    }

    /**
     * Staff cancels any booking (MANAGER, ADMIN, SUPER_ADMIN).
     * Same logic as customer cancel but not scoped to a customer ID.
     */
    @Transactional
    public Mono<BookingDTO> cancelBookingByStaff(
            UUID bookingId, String reason, String staffId) {

        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    if (!booking.getStatus().isCancellable()) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Cannot cancel a booking with status: "
                                        + booking.getStatus().getDescription());
                    }

                    TourAvailability slot = booking.getAvailability();
                    slot.releaseSlots(booking.getTravelerCount());
                    availabilityRepository.save(slot);

                    booking.cancel("[Staff: " + staffId + "] " + reason);
                    Booking saved = bookingRepository.save(booking);

                    log.warn("🚫 Booking {} cancelled by staff {} — reason: {}",
                            bookingId, staffId, reason);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(OptimisticLockingFailureException.class, e ->
                        Mono.error(new CustomException(HttpStatus.CONFLICT,
                                "Booking was modified concurrently. Please try again.")))
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Staff cancellation failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Cancellation failed. Please try again."));
                });
    }

    // ── CONFIRM ───────────────────────────────────────────────────────────────

    /**
     * Staff confirms a booking after payment is verified.
     * Called by MANAGER/ADMIN or a payment webhook handler.
     *
     * @param bookingId        the booking to confirm
     * @param paymentReference external payment provider reference
     */
    @Transactional
    public Mono<BookingDTO> confirmBooking(UUID bookingId, String paymentReference) {
        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    if (booking.getStatus() != BookingStatus.PENDING_PAYMENT) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Only PENDING_PAYMENT bookings can be confirmed. "
                                        + "Current status: " + booking.getStatus().name());
                    }

                    // Booking.confirm() sets status → CONFIRMED, paymentReference, paidAt
                    booking.confirm(paymentReference);
                    Booking saved = bookingRepository.save(booking);

                    log.info("✅ Booking confirmed: {} payment: {}", bookingId, paymentReference);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Confirm failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Confirmation failed."));
                });
    }

    // ── COMPLETE ─────────────────────────────────────────────────────────────

    /**
     * Marks a booking as COMPLETED after the tour has run.
     * Typically called by a scheduled job or by staff post-tour.
     */
    @Transactional
    public Mono<BookingDTO> completeBooking(UUID bookingId) {
        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    if (booking.getStatus() != BookingStatus.CONFIRMED) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Only CONFIRMED bookings can be completed. "
                                        + "Current status: " + booking.getStatus().name());
                    }

                    booking.complete();
                    Booking saved = bookingRepository.save(booking);

                    log.info("🏁 Booking completed: {}", bookingId);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Complete failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Failed to complete booking."));
                });
    }

    // ── REFUND ────────────────────────────────────────────────────────────────

    /**
     * Marks a booking as REFUNDED after payment is returned to customer.
     * ADMIN/SUPER_ADMIN only (enforced at controller level).
     */
    @Transactional
    public Mono<BookingDTO> refundBooking(UUID bookingId, String refundReference) {
        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    if (booking.getStatus() != BookingStatus.CANCELLED) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Only CANCELLED bookings can be refunded. "
                                        + "Current status: " + booking.getStatus().name());
                    }

                    booking.refund(refundReference);
                    Booking saved = bookingRepository.save(booking);

                    log.info("💰 Booking refunded: {} ref: {}", bookingId, refundReference);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Refund failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Refund processing failed."));
                });
    }

    // ── STATISTICS ────────────────────────────────────────────────────────────

    /**
     * Returns counts per status — used by the admin dashboard stats card.
     */
    public Mono<BookingStats> getStats() {
        return Mono.fromCallable(() -> new BookingStats(
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.PENDING_PAYMENT),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.CONFIRMED),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.COMPLETED),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.CANCELLED),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.REFUNDED)
                ))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public record BookingStats(
            long pendingPayment,
            long confirmed,
            long completed,
            long cancelled,
            long refunded
    ) {
        public long totalActive() { return pendingPayment + confirmed; }
    }
}