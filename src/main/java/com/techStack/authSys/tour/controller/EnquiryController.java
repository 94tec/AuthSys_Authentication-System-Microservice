package com.techStack.authSys.tour.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.tour.dto.request.CreateEnquiryRequest;
import com.techStack.authSys.tour.dto.request.SubmitPaymentRequest;
import com.techStack.authSys.tour.dto.response.*;
import com.techStack.authSys.tour.models.TourEnquiryStatus;
import com.techStack.authSys.tour.services.EnquiryLifecycleService;
import com.techStack.authSys.tour.services.EnquiryQuoteService;
import com.techStack.authSys.tour.services.PaymentSubmissionService;
import com.techStack.authSys.tour.services.TourEnquiryService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

/**
 * Enquiry endpoints used by customers (and the staff list-by-tour view).
 * Admin-only enquiry management stays in AdminEnquiryController under /api/admin/enquiries.
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
public class EnquiryController {

    private final TourEnquiryService tourEnquiryService;
    private final EnquiryLifecycleService lifecycleService;
    private final EnquiryQuoteService quoteService;
    private final PaymentSubmissionService paymentSubmissionService;

    // ── Per-tour ─────────────────────────────────────────────────────

    @PostMapping("/tours/{tourId}/enquiries")
    public Mono<ResponseEntity<EnquiryResponse>> create(
            @PathVariable UUID tourId,
            @Valid @RequestBody CreateEnquiryRequest request,
            @AuthenticationPrincipal CustomUserDetails user) {
        return tourEnquiryService.createEnquiry(tourId, user.getUserId(), request)
                .map(res -> ResponseEntity.status(HttpStatus.CREATED).body(res));
    }

    @GetMapping("/tours/{tourId}/enquiries")
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN','MANAGER','OPERATOR')") // method-level overrides class-level
    public Mono<ResponseEntity<?>> listForTour(
            @PathVariable UUID tourId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return tourEnquiryService.listForTour(tourId, PageRequest.of(page, Math.min(size, 100)))
                .map(ResponseEntity::ok);
    }

    // ── Customer self-service ────────────────────────────────────────

    @GetMapping("/me/enquiries")
    public Mono<Page<EnquirySummaryResponse>> myEnquiries(
            @RequestParam(required = false) TourEnquiryStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal CustomUserDetails user) {
        return lifecycleService.myEnquiries(user.getUserId(), status, PageRequest.of(page, Math.min(size, 50)));
    }

    @GetMapping("/me/enquiries/{id}")
    public Mono<EnquiryDetailResponse> myEnquiryDetail(
            @PathVariable UUID id,
            @AuthenticationPrincipal CustomUserDetails user) {
        return lifecycleService.getMyDetail(id, user.getUserId());
    }

    public record AcceptQuoteRequest(
            @AssertTrue(message = "You must accept the payment terms to continue") boolean termsAccepted) {}

    @PostMapping("/me/enquiries/{enquiryId}/quotes/{quoteId}/accept")
    public Mono<QuoteResponse> acceptQuote(
            @PathVariable UUID enquiryId, @PathVariable UUID quoteId,
            @Valid @RequestBody AcceptQuoteRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return quoteService.acceptQuote(enquiryId, quoteId, user.getUserId());
    }

    @PostMapping("/me/enquiries/{enquiryId}/quotes/{quoteId}/payment-submissions")
    public Mono<PaymentSubmissionResponse> submitPayment(
            @PathVariable UUID enquiryId, @PathVariable UUID quoteId,
            @Valid @RequestBody SubmitPaymentRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return paymentSubmissionService.submitPayment(enquiryId, quoteId, user.getUserId(), req);
    }

    @GetMapping("/me/enquiries/{enquiryId}/payment-submissions")
    public Mono<List<PaymentSubmissionResponse>> myPaymentSubmissions(
            @PathVariable UUID enquiryId, @AuthenticationPrincipal CustomUserDetails user) {
        return paymentSubmissionService.listForEnquiry(enquiryId, user.getUserId());
    }

    @GetMapping("/me/enquiries/{enquiryId}/quotes/{quoteId}/pdf")
    public Mono<ResponseEntity<byte[]>> downloadMyQuotePdf(
            @PathVariable UUID enquiryId, @PathVariable UUID quoteId,
            @AuthenticationPrincipal CustomUserDetails user) {
        return quoteService.generateQuotePdf(enquiryId, quoteId, user.getUserId(), false)
                .map(bytes -> ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_PDF)
                        .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"quote-" + quoteId + ".pdf\"")
                        .body(bytes));
    }
}