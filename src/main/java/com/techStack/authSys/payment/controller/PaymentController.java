package com.techStack.authSys.payment.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.common.dto.ApiResponse;
import com.techStack.authSys.payment.dto.request.StkPushRequest;
import com.techStack.authSys.payment.dto.response.PaymentResponse;
import com.techStack.authSys.payment.dto.response.PaymentStatusResponse;
import com.techStack.authSys.payment.dto.response.PaymentStatsResponse;
import com.techStack.authSys.payment.dto.response.StkPushResponse;
import com.techStack.authSys.payment.service.PaymentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * PaymentController — /api/payments/**
 *
 * USER (authenticated customer):
 *   POST /api/payments/mpesa/stk-push         initiate payment
 *   GET  /api/payments/{id}/status            poll payment status
 *   GET  /api/payments/me                     own payment history
 *
 * MANAGER, ADMIN, SUPER_ADMIN (staff):
 *   GET  /api/payments/booking/{bookingId}    all payments for a booking
 *
 * ADMIN, SUPER_ADMIN:
 *   POST /api/payments/booking/{bookingId}/refund   mark payment refunded
 *   GET  /api/payments/admin/stats                  revenue + status counts
 *
 * Note: MpesaCallbackController is a SEPARATE class at /api/payments/mpesa/callback
 * with no auth, registered on a separate path to allow IP whitelisting.
 */
@Slf4j
@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
@Tag(name = "Payments", description = "M-Pesa payment processing for enquire-button.tsx bookings")
public class PaymentController {

    private final PaymentService paymentService;

    // ── USER: initiate payment ────────────────────────────────────────────────

    @PostMapping("/mpesa/stk-push")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Initiate M-Pesa STK push — sends payment prompt to customer's phone")
    public Mono<StkPushResponse> initiateStkPush(
            @Valid @RequestBody StkPushRequest request,
            @AuthenticationPrincipal CustomUserDetails user) {

        log.info("STK push request: bookingId={} phone={} customerId={}",
            request.bookingId(), request.phoneNumber(), user.getUserId());

        return paymentService.initiateMpesaPayment(request, user.getUserId());
    }

    // ── USER: poll payment status ─────────────────────────────────────────────

    @GetMapping("/{paymentId}/status")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Poll payment status — frontend calls this after STK push until not PENDING")
    public Mono<PaymentStatusResponse> getPaymentStatus(
            @PathVariable UUID paymentId,
            @AuthenticationPrincipal CustomUserDetails user) {

        return paymentService.getPaymentStatus(paymentId, user.getUserId());
    }

    // ── USER: own payment history ─────────────────────────────────────────────

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Get own payment history")
    public Flux<PaymentResponse> getMyPayments(
            @AuthenticationPrincipal CustomUserDetails user) {

        return paymentService.getMyPayments(user.getUserId());
    }

    // ── STAFF: payments by booking ────────────────────────────────────────────

    @GetMapping("/booking/{bookingId}")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Get all payment attempts for a booking — staff view")
    public Flux<PaymentResponse> getPaymentsByBooking(@PathVariable UUID bookingId) {
        return paymentService.getPaymentsByBooking(bookingId);
    }

    // ── ADMIN: refund ─────────────────────────────────────────────────────────

    @PostMapping("/booking/{bookingId}/refund")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Mark payment as refunded after booking cancellation — Admin only")
    public Mono<ResponseEntity<ApiResponse<PaymentResponse>>> processRefund(
            @PathVariable UUID bookingId) {

        log.warn("Refund initiated for bookingId={}", bookingId);

        return paymentService.processRefund(bookingId)
            .map(resp -> ResponseEntity.ok(
                new ApiResponse<>(true, "Payment marked as refunded", resp)));
    }

    // ── ADMIN: stats ──────────────────────────────────────────────────────────

    @GetMapping("/admin/stats")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Payment status counts and total revenue — admin dashboard")
    public Mono<ResponseEntity<ApiResponse<PaymentStatsResponse>>> getStats() {
        return paymentService.getStats()
            .map(stats -> ResponseEntity.ok(
                new ApiResponse<>(true, "Payment statistics", stats)));
    }
}
