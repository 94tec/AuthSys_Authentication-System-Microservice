package com.techStack.authSys.tour.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.tour.dto.request.CreateBookingFromPaymentRequest;
import com.techStack.authSys.tour.dto.request.RejectPaymentRequest;
import com.techStack.authSys.tour.dto.response.BookingCreatedResponse;
import com.techStack.authSys.tour.dto.response.PaymentSubmissionResponse;
import com.techStack.authSys.tour.services.EnquiryBookingService;
import com.techStack.authSys.tour.services.PaymentSubmissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

// New: AdminPaymentController.java
@RestController
@RequestMapping("/api/admin/payment-submissions")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN','MANAGER')")
public class AdminPaymentController {

    private final PaymentSubmissionService paymentSubmissionService;
    private final EnquiryBookingService enquiryBookingService;

    @GetMapping
    public Mono<Page<PaymentSubmissionResponse>> list(
            @RequestParam(defaultValue = "pending") String view,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return paymentSubmissionService.listByView(view, PageRequest.of(page, Math.min(size, 100)));
    }

    @PostMapping("/{id}/verify")
    public Mono<PaymentSubmissionResponse> verify(
            @PathVariable UUID id, @AuthenticationPrincipal CustomUserDetails user) {
        return paymentSubmissionService.verifyPayment(id, user.getUserId());
    }

    @PostMapping("/{id}/reject")
    public Mono<PaymentSubmissionResponse> reject(
            @PathVariable UUID id, @Valid @RequestBody RejectPaymentRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return paymentSubmissionService.rejectPayment(id, user.getUserId(), req);
    }

    @PostMapping("/{id}/create-booking")
    public Mono<BookingCreatedResponse> createBooking(
            @PathVariable UUID id, @Valid @RequestBody CreateBookingFromPaymentRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return enquiryBookingService.createBookingFromVerifiedPayment(id, user.getUserId(), req);
    }

}
