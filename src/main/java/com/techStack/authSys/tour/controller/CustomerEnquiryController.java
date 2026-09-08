package com.techStack.authSys.tour.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.payment.models.Payment;
import com.techStack.authSys.tour.dto.request.SubmitPaymentRequest;
import com.techStack.authSys.tour.dto.response.EnquiryDetailResponse;
import com.techStack.authSys.tour.dto.response.EnquirySummaryResponse;
import com.techStack.authSys.tour.dto.response.PaymentSubmissionResponse;
import com.techStack.authSys.tour.dto.response.QuoteResponse;
import com.techStack.authSys.tour.models.TourEnquiryStatus;
import com.techStack.authSys.tour.services.EnquiryLifecycleService;
import com.techStack.authSys.tour.services.EnquiryQuoteService;
import com.techStack.authSys.tour.services.PaymentSubmissionService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/me/enquiries")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
public class CustomerEnquiryController {

    private final EnquiryLifecycleService lifecycleService;
    private final EnquiryQuoteService quoteService;
    private final PaymentSubmissionService paymentSubmissionService;

    @GetMapping
    public Mono<Page<EnquirySummaryResponse>> myEnquiries(
            @RequestParam(required = false) TourEnquiryStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal CustomUserDetails user) {
        return lifecycleService.myEnquiries(user.getUserId(), status, PageRequest.of(page, Math.min(size, 50)));
    }

    @GetMapping("/{id}")
    public Mono<EnquiryDetailResponse> myEnquiryDetail(
            @PathVariable UUID id,
            @AuthenticationPrincipal CustomUserDetails user) {
        return lifecycleService.getMyDetail(id, user.getUserId());
    }
    //
    public record AcceptQuoteRequest(
            @AssertTrue(message = "You must accept the payment terms to continue")
            boolean termsAccepted)
    {}

    @PostMapping("/{enquiryId}/quotes/{quoteId}/accept")
    public Mono<QuoteResponse> acceptQuote(
            @PathVariable UUID enquiryId, @PathVariable UUID quoteId,
            @Valid @RequestBody AcceptQuoteRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return quoteService.acceptQuote(enquiryId, quoteId, user.getUserId());
    }

    @PostMapping("/{enquiryId}/quotes/{quoteId}/payment-submissions")
    public Mono<PaymentSubmissionResponse> submitPayment(
            @PathVariable UUID enquiryId, @PathVariable UUID quoteId,
            @Valid @RequestBody SubmitPaymentRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return paymentSubmissionService.submitPayment(enquiryId, quoteId, user.getUserId(), req);
    }

    @GetMapping("/{enquiryId}/payment-submissions")
    public Mono<List<PaymentSubmissionResponse>> myPaymentSubmissions(
            @PathVariable UUID enquiryId, @AuthenticationPrincipal CustomUserDetails user) {
        return paymentSubmissionService.listForEnquiry(enquiryId, user.getUserId());
    }

    @GetMapping("/{enquiryId}/quotes/{quoteId}/pdf")
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