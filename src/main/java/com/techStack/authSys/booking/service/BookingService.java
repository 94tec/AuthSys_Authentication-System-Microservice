package com.techStack.authSys.booking.service;

import com.techStack.authSys.availability.models.AvailabilityStatus;
import com.techStack.authSys.availability.models.TourAvailability;
import com.techStack.authSys.availability.repository.TourAvailabilityRepository;
import com.techStack.authSys.booking.dto.request.CreateBookingRequest;
import com.techStack.authSys.booking.dto.response.BookingDTO;
import com.techStack.authSys.booking.mapper.BookingMapper;
import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.models.BookingStatus;
import com.techStack.authSys.booking.models.BookingTraveler;
import com.techStack.authSys.booking.models.PaymentStatus;
import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.common.exception.CustomException;
import com.techStack.authSys.tour.models.Tour;
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
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.Period;
import java.time.Year;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Booking Service
 *
 * Handles the full booking lifecycle:
 *   CREATE   → validate → reserve slots (optimistic lock) → persist
 *   READ     → customer's own bookings, staff all-bookings
 *   CANCEL   → release slots → soft-delete booking
 *   CONFIRM  → manual staff confirm (no payment) OR recordPayment() (auto-confirms)
 *   PAYMENT  → recordPayment() tracks deposit/balance, drives PaymentStatus
 *   COMPLETE → mark completed (post-enquire-button.tsx)
 *   NO_SHOW  → mark no-show (post-departure, customer didn't show)
 *   REFUND   → refundPayment() (staff, requires CANCELLED + paid)
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

    /** Age (in years, at travel date) below which a traveler is counted as a child for party-split purposes. */
    private static final int CHILD_AGE_THRESHOLD = 12;

    // ── CREATE ───────────────────────────────────────────────────────────────

    /**
     * Create a booking for an authenticated USER.
     *
     * Steps:
     *   1. Load enquire-button.tsx (must be active, not deleted)
     *   2. Load availability slot (must not be CLOSED/CANCELLED, not past booking deadline)
     *   3. Validate slot belongs to enquire-button.tsx
     *   4. Check capacity via hasAvailability()
     *   5. Prevent duplicate active booking (same customer, same slot)
     *   6. Snapshot pricing at booking time
     *   7. Build booking + travelers
     *   8. reserveSlots() on the availability (mutates availableSlots + status)
     *   9. Save availability (triggers optimistic lock check)
     *  10. Save booking
     *  11. Increment enquire-button.tsx.totalBookings counter
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

                    // 1. Load enquire-button.tsx
                    Tour tour = tourRepository
                            .findByIdAndDeletedFalse(req.tourId())
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND,
                                    "Tour not found or no longer available"));

                    if (!Boolean.TRUE.equals(tour.getActive())) {
                        throw new IllegalArgumentException(
                                "Cannot create slots for an inactive enquire-button.tsx: " + tour.getName()
                        );
                    }

                    // 2. Load availability slot
                    TourAvailability slot = availabilityRepository
                            .findById(req.availabilityId())
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND,
                                    "Availability slot not found"));

                    // 3. Validate slot belongs to requested enquire-button.tsx
                    if (!slot.getTour().getId().equals(tour.getId())) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Availability slot does not belong to this enquire-button.tsx");
                    }

                    // 4. Slot must not be manually closed or cancelled.
                    // Capacity-driven states (OPEN / LIMITED / FULL) are NOT
                    // checked here — hasAvailability() in step 7 is the single
                    // source of truth for those, since LIMITED slots are still
                    // bookable and a plain "== OPEN" check would wrongly reject them.
                    if (slot.getStatus() == AvailabilityStatus.CLOSED
                            || slot.getStatus() == AvailabilityStatus.CANCELLED) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "This enquire-button.tsx date is no longer available ("
                                        + slot.getStatus().name() + ")");
                    }

                    // 5. Past booking deadline check
                    if (slot.getBookingDeadline() != null
                            && OffsetDateTime.now().isAfter(slot.getBookingDeadline())) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Booking deadline for this date has passed");
                    }

                    // 6. Past enquire-button.tsx date check
                    if (slot.getDate().isBefore(LocalDate.now())) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Cannot book a enquire-button.tsx date in the past");
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
                                "You already have an active booking for this enquire-button.tsx date");
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
                    // Uses the SLOT's effective price/currency (respects any
                    // per-date priceOverride set via AvailabilityService), not
                    // the enquire-button.tsx's base price directly — a slot override would
                    // otherwise be silently ignored at booking time.
                    // Later changes to enquire-button.tsx.price or the slot's override do NOT
                    // affect confirmed bookings, since this snapshot is frozen.
                    BigDecimal pricePerTraveler = slot.getEffectivePrice();
                    BigDecimal totalPrice = pricePerTraveler
                            .multiply(BigDecimal.valueOf(req.travelerCount()));

                    // 10a. Adults/children split — derived from each traveler's
                    // dateOfBirth against the travel date, rather than requiring
                    // a new request field. Travelers without a DOB (optional,
                    // e.g. domestic bookings) are counted as adults.
                    int adults = 0;
                    int children = 0;
                    for (CreateBookingRequest.TravelerRequest t : req.travelers()) {
                        boolean isChild = t.dateOfBirth() != null
                                && Period.between(t.dateOfBirth(), slot.getDate()).getYears()
                                < CHILD_AGE_THRESHOLD;
                        if (isChild) children++; else adults++;
                    }

                    // 10b. Deposit — enquire-button.tsx.depositPercentage of totalPrice, or full
                    // amount upfront if the enquire-button.tsx has no deposit policy configured.
                    BigDecimal depositAmount = tour.getDepositPercentage() != null
                            ? totalPrice.multiply(tour.getDepositPercentage())
                            .divide(BigDecimal.valueOf(100), 2, RoundingMode.HALF_UP)
                            : totalPrice;

                    // 11. Build booking
                    Booking booking = Booking.builder()
                            .bookingReference(generateBookingReference())
                            .customerId(customerId)
                            .customerEmail(customerEmail)
                            .customerName(customerName)
                            .tour(tour)
                            .availability(slot)
                            .tourDate(slot.getDate())
                            .tourName(tour.getName())
                            .travelerCount(req.travelerCount())
                            .numberOfAdults(adults)
                            .numberOfChildren(children)
                            .pricePerTraveler(pricePerTraveler)
                            .subtotal(totalPrice)
                            .discount(BigDecimal.ZERO)
                            .totalPrice(totalPrice)
                            .currency(slot.getEffectiveCurrency().name())
                            .depositAmount(depositAmount)
                            .balanceAmount(totalPrice)
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

                    log.info("✅ Booking created: {} customer: {} enquire-button.tsx: {} date: {} travelers: {}",
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
     * Returns only active bookings (PENDING + CONFIRMED) for a customer.
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
     * Returns all bookings for a specific enquire-button.tsx date.
     * Used by operations staff for daily enquire-button.tsx manifests.
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
     * Returns all bookings for a specific enquire-button.tsx.
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
     * Staff manually confirms a PENDING booking without recording a payment
     * — e.g. a pay-on-arrival arrangement, or a staff override.
     * For the normal deposit/payment flow, use recordPayment() instead,
     * which auto-confirms the booking as a side effect.
     */
    @Transactional
    public Mono<BookingDTO> confirmBooking(UUID bookingId) {
        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    // Booking.confirm() sets status → CONFIRMED
                    booking.confirm();
                    Booking saved = bookingRepository.save(booking);

                    log.info("✅ Booking manually confirmed: {}", bookingId);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(IllegalStateException.class, e ->
                        Mono.error(new CustomException(HttpStatus.BAD_REQUEST, e.getMessage())))
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Confirm failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Confirmation failed."));
                });
    }

    /**
     * Records a payment (deposit or balance) against a booking — the normal
     * path to CONFIRMED. Typically called by a payment webhook handler once
     * a payment provider confirms funds received; also usable by staff for
     * manually-reconciled payments (bank transfer, cash, etc).
     *
     * @param bookingId        the booking receiving payment
     * @param amount           amount received, in the booking's currency
     * @param paymentReference external payment provider reference
     */
    @Transactional
    public Mono<BookingDTO> recordPayment(UUID bookingId, BigDecimal amount, String paymentReference) {
        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    // Booking.recordPayment() updates amountPaid/balanceAmount/
                    // paymentStatus, and auto-confirms a PENDING booking.
                    booking.recordPayment(amount, paymentReference);
                    Booking saved = bookingRepository.save(booking);

                    log.info("💳 Payment recorded: booking={} amount={} paymentStatus={} ref={}",
                            bookingId, amount, saved.getPaymentStatus(), paymentReference);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(IllegalArgumentException.class, e ->
                        Mono.error(new CustomException(HttpStatus.BAD_REQUEST, e.getMessage())))
                .onErrorResume(IllegalStateException.class, e ->
                        Mono.error(new CustomException(HttpStatus.BAD_REQUEST, e.getMessage())))
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Payment recording failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Failed to record payment."));
                });
    }

    // ── COMPLETE ─────────────────────────────────────────────────────────────

    /**
     * Marks a booking as COMPLETED after the enquire-button.tsx has run.
     * Typically called by a scheduled job or by staff post-enquire-button.tsx.
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

    // ── NO-SHOW ──────────────────────────────────────────────────────────────

    /**
     * Marks a CONFIRMED booking as NO_SHOW after the enquire-button.tsx departs without
     * the customer. Does not release the slot (the seat was held and the
     * cost incurred regardless) and does not touch payment — refunding a
     * no-show, if the business chooses to, is a separate explicit action
     * via refundBooking().
     */
    @Transactional
    public Mono<BookingDTO> markNoShow(UUID bookingId) {
        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    booking.markNoShow();
                    Booking saved = bookingRepository.save(booking);

                    log.info("👻 Booking marked NO_SHOW: {}", bookingId);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(IllegalStateException.class, e ->
                        Mono.error(new CustomException(HttpStatus.BAD_REQUEST, e.getMessage())))
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ No-show marking failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Failed to mark booking as no-show."));
                });
    }

    // ── REFUND ────────────────────────────────────────────────────────────────

    /**
     * Marks a booking's payment as refunded after money is returned to the
     * customer. ADMIN/SUPER_ADMIN only (enforced at controller). Booking
     * must already be CANCELLED, with a PARTIALLY_PAID or PAID payment status.
     */
    @Transactional
    public Mono<BookingDTO> refundBooking(UUID bookingId, String refundReference) {
        return Mono.fromCallable(() -> {
                    Booking booking = bookingRepository
                            .findByIdAndDeletedFalse(bookingId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Booking not found"));

                    // Booking.refundPayment() validates status == CANCELLED and
                    // paymentStatus is PARTIALLY_PAID/PAID, then sets REFUNDED.
                    booking.refundPayment(refundReference);
                    Booking saved = bookingRepository.save(booking);

                    log.info("💰 Booking refunded: {} ref: {}", bookingId, refundReference);

                    return bookingMapper.toDTO(saved);

                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(IllegalStateException.class, e ->
                        Mono.error(new CustomException(HttpStatus.BAD_REQUEST, e.getMessage())))
                .onErrorResume(CustomException.class, Mono::error)
                .onErrorResume(e -> {
                    log.error("❌ Refund failed for {}: {}", bookingId, e.getMessage(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR, "Refund processing failed."));
                });
    }

    // ── Booking reference ────────────────────────────────────────────────────

    /**
     * Generates a human-readable, customer-facing reference like
     * "DMC-2026-04821". Retries on the (extremely unlikely) chance of a
     * collision, since the column has a unique constraint.
     */
    public String generateBookingReference() {
        String reference;
        int attempts = 0;
        do {
            reference = "DMC-" + Year.now().getValue() + "-"
                    + String.format("%05d", ThreadLocalRandom.current().nextInt(0, 100_000));
            attempts++;
        } while (bookingRepository.existsByBookingReference(reference) && attempts < 10);
        return reference;
    }

    // ── STATISTICS ────────────────────────────────────────────────────────────

    /**
     * Returns counts per BookingStatus and per PaymentStatus — used by the
     * admin dashboard stats card. Two independent breakdowns since a
     * booking's trip status and payment status now vary independently.
     */
    public Mono<BookingStats> getStats() {
        return Mono.fromCallable(() -> new BookingStats(
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.PENDING_PAYMENT),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.CONFIRMED),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.COMPLETED),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.CANCELLED),
                        bookingRepository.countByStatusAndDeletedFalse(BookingStatus.NO_SHOW),
                        bookingRepository.countByPaymentStatusAndDeletedFalse(PaymentStatus.UNPAID),
                        bookingRepository.countByPaymentStatusAndDeletedFalse(PaymentStatus.PARTIALLY_PAID),
                        bookingRepository.countByPaymentStatusAndDeletedFalse(PaymentStatus.PAID),
                        bookingRepository.countByPaymentStatusAndDeletedFalse(PaymentStatus.REFUNDED)
                ))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public record BookingStats(
            long pending,
            long confirmed,
            long completed,
            long cancelled,
            long noShow,
            long unpaid,
            long partiallyPaid,
            long paid,
            long refunded
    ) {
        public long totalActive() { return pending + confirmed; }
    }
}