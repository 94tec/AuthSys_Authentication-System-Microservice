package com.techStack.authSys.booking.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.booking.dto.request.CreateBookingRequest;
import com.techStack.authSys.booking.dto.response.BookingDTO;
import com.techStack.authSys.booking.models.BookingStatus;
import com.techStack.authSys.booking.service.BookingService;
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
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.UUID;

/**
 * Booking endpoints for Damuchi Safaris.
 *
 * Customer (USER role):
 *   POST  /api/bookings              — create a booking
 *   GET   /api/bookings/me           — all own bookings
 *   GET   /api/bookings/me/{id}      — single own booking
 *   GET   /api/bookings/me/active    — active (upcoming) bookings
 *   POST  /api/bookings/{id}/cancel  — cancel own booking
 *
 * Staff (MANAGER, ADMIN, SUPER_ADMIN):
 *   GET   /api/bookings                — all bookings, optional ?status= filter
 *   GET   /api/bookings/by-date        — daily manifest by date
 *   GET   /api/bookings/by-enquire-button.tsx/{id}   — all bookings for a enquire-button.tsx
 *   POST  /api/bookings/{id}/cancel    — cancel any booking
 *   POST  /api/bookings/{id}/confirm   — manually confirm (no payment — e.g. pay-on-arrival)
 *   POST  /api/bookings/{id}/payments  — record a payment (deposit or balance; auto-confirms)
 *   POST  /api/bookings/{id}/complete  — mark completed post-enquire-button.tsx
 *   POST  /api/bookings/{id}/no-show   — mark customer as a no-show
 *   GET   /api/bookings/stats          — status + payment-status counts for dashboard
 *
 * Admin only (ADMIN, SUPER_ADMIN):
 *   POST  /api/bookings/{id}/refund  — mark payment refunded (booking must be CANCELLED)
 */
@Slf4j
@RestController
@RequestMapping("/api/bookings")
@RequiredArgsConstructor
@Tag(name = "Bookings", description = "Damuchi Safaris booking management")
public class BookingController {

    private final BookingService bookingService;

    // ── Customer: create ──────────────────────────────────────────────────────

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Create a booking — authenticated customers only")
    public Mono<BookingDTO> createBooking(
            @Valid @RequestBody CreateBookingRequest request,
            @AuthenticationPrincipal CustomUserDetails user) {

        log.info("Booking request: enquire-button.tsx={} slots={} customer={}",
                request.tourId(), request.travelerCount(), user.getUserId());

        return bookingService.createBooking(
                user.getUserId(),
                user.getUsername(),
                user.getDisplayName(),
                request);
    }

    // ── Customer: read own bookings ───────────────────────────────────────────

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Get all own bookings — newest first")
    public Flux<BookingDTO> myBookings(
            @AuthenticationPrincipal CustomUserDetails user) {
        return bookingService.getMyBookings(user.getUserId());
    }

    @GetMapping("/me/{id}")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Get a single own booking by ID")
    public Mono<BookingDTO> myBookingById(
            @PathVariable UUID id,
            @AuthenticationPrincipal CustomUserDetails user) {
        return bookingService.getMyBookingById(user.getUserId(), id);
    }

    @GetMapping("/me/active")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Get active (PENDING + CONFIRMED) bookings — upcoming trips dashboard")
    public Flux<BookingDTO> myActiveBookings(
            @AuthenticationPrincipal CustomUserDetails user) {
        return bookingService.getMyActiveBookings(user.getUserId());
    }

    // ── Customer: cancel own booking ──────────────────────────────────────────

    @PostMapping("/me/{id}/cancel")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Cancel own booking")
    public Mono<BookingDTO> cancelMyBooking(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "Cancelled by customer") String reason,
            @AuthenticationPrincipal CustomUserDetails user) {
        return bookingService.cancelMyBooking(user.getUserId(), id, reason);
    }

    // ── Staff: read all bookings ──────────────────────────────────────────────

    @GetMapping
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "List all bookings — optional status filter")
    public Flux<BookingDTO> getAllBookings(
            @RequestParam(required = false)
            @Parameter(description = "Filter by BookingStatus enum value")
            BookingStatus status) {
        return bookingService.getAllBookings(status);
    }

    @GetMapping("/by-date")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Get bookings by enquire-button.tsx date — daily manifest")
    public Flux<BookingDTO> bookingsByDate(
            @RequestParam
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
            @Parameter(description = "Date in ISO format: YYYY-MM-DD")
            LocalDate date) {
        return bookingService.getBookingsByDate(date);
    }

    @GetMapping("/by-enquire-button.tsx/{tourId}")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Get all bookings for a specific enquire-button.tsx")
    public Flux<BookingDTO> bookingsByTour(@PathVariable UUID tourId) {
        return bookingService.getBookingsByTour(tourId);
    }

    // ── Staff: cancel any booking ─────────────────────────────────────────────

    @PostMapping("/{bookingId}/cancel")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Staff cancel any booking")
    public Mono<BookingDTO> staffCancel(
            @PathVariable UUID bookingId,
            @RequestParam String reason,
            @AuthenticationPrincipal CustomUserDetails staff) {
        return bookingService.cancelBookingByStaff(bookingId, reason, staff.getUserId());
    }

    // ── Staff: manual confirm (no payment) ────────────────────────────────────

    @PostMapping("/{bookingId}/confirm")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Manually confirm a PENDING booking without recording a payment (e.g. pay-on-arrival)")
    public Mono<ResponseEntity<ApiResponse<BookingDTO>>> confirmBooking(
            @PathVariable UUID bookingId) {
        return bookingService.confirmBooking(bookingId)
                .map(dto -> ResponseEntity.ok(
                        new ApiResponse<>(true, "Booking confirmed", dto)));
    }

    // ── Staff: record a payment ───────────────────────────────────────────────

    @PostMapping("/{bookingId}/payments")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Record a payment (deposit or balance) against a booking — auto-confirms a PENDING booking")
    public Mono<ResponseEntity<ApiResponse<BookingDTO>>> recordPayment(
            @PathVariable UUID bookingId,
            @RequestParam BigDecimal amount,
            @RequestParam String paymentReference) {
        return bookingService.recordPayment(bookingId, amount, paymentReference)
                .map(dto -> ResponseEntity.ok(
                        new ApiResponse<>(true, "Payment recorded", dto)));
    }

    // ── Staff: complete booking post-enquire-button.tsx ─────────────────────────────────────

    @PostMapping("/{bookingId}/complete")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Mark a booking as completed after the enquire-button.tsx has run")
    public Mono<ResponseEntity<ApiResponse<BookingDTO>>> completeBooking(
            @PathVariable UUID bookingId) {
        return bookingService.completeBooking(bookingId)
                .map(dto -> ResponseEntity.ok(
                        new ApiResponse<>(true, "Booking marked as completed", dto)));
    }

    // ── Staff: mark no-show ───────────────────────────────────────────────────

    @PostMapping("/{bookingId}/no-show")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Mark a confirmed booking as a no-show after the enquire-button.tsx departs")
    public Mono<ResponseEntity<ApiResponse<BookingDTO>>> markNoShow(
            @PathVariable UUID bookingId) {
        return bookingService.markNoShow(bookingId)
                .map(dto -> ResponseEntity.ok(
                        new ApiResponse<>(true, "Booking marked as no-show", dto)));
    }

    // ── Admin: refund ─────────────────────────────────────────────────────────

    @PostMapping("/{bookingId}/refund")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Mark a cancelled booking as refunded — Admin only")
    public Mono<ResponseEntity<ApiResponse<BookingDTO>>> refundBooking(
            @PathVariable UUID bookingId,
            @RequestParam String refundReference) {
        return bookingService.refundBooking(bookingId, refundReference)
                .map(dto -> ResponseEntity.ok(
                        new ApiResponse<>(true, "Booking refunded", dto)));
    }

    // ── Stats: admin dashboard ─────────────────────────────────────────────────

    @GetMapping("/stats")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Booking status counts for the admin dashboard")
    public Mono<BookingService.BookingStats> getStats() {
        return bookingService.getStats();
    }
}