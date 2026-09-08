package com.techStack.authSys.tour.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.tour.dto.request.*;
import com.techStack.authSys.tour.dto.response.*;
import com.techStack.authSys.tour.models.TourEnquiryStatus;
import com.techStack.authSys.tour.services.EnquiryLifecycleService;
import com.techStack.authSys.tour.services.EnquiryQuoteService;
import jakarta.validation.Valid;
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

import java.util.UUID;

@RestController
@RequestMapping("/api/admin/enquiries")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN','MANAGER','OPERATOR')")
public class AdminEnquiryController {

    private final EnquiryLifecycleService lifecycleService;
    private final EnquiryQuoteService quoteService;

    @GetMapping
    public Mono<Page<EnquirySummaryResponse>> search(
            @RequestParam(required = false) TourEnquiryStatus status,
            @RequestParam(required = false) String assignedTo,
            @RequestParam(required = false) UUID tourId,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return lifecycleService.search(status, assignedTo, tourId, search,
                PageRequest.of(page, Math.min(size, 100)));
    }

    @GetMapping("/{id}")
    public Mono<EnquiryDetailResponse> detail(@PathVariable UUID id) {
        return lifecycleService.getDetail(id);
    }

    @GetMapping("/dashboard/summary")
    public Mono<EnquiryDashboardSummary> dashboard() {
        return lifecycleService.dashboardSummary();
    }

    @PatchMapping("/{id}/status")
    public Mono<EnquiryDetailResponse> updateStatus(
            @PathVariable UUID id, @Valid @RequestBody UpdateEnquiryStatusRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return lifecycleService.updateStatus(id, user.getUserId(), req);
    }

    @PatchMapping("/{id}/assign")
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN','MANAGER')")
    public Mono<ResponseEntity<Void>> assign(
            @PathVariable UUID id, @Valid @RequestBody AssignEnquiryRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return lifecycleService.assign(id, user.getUserId(), req)
                .thenReturn(ResponseEntity.noContent().build());
    }

    @PostMapping("/{id}/notes")
    public Mono<ResponseEntity<Void>> addNote(
            @PathVariable UUID id, @RequestBody String note,
            @AuthenticationPrincipal CustomUserDetails user) {
        return lifecycleService.addNote(id, user.getUserId(), note)
                .thenReturn(ResponseEntity.status(HttpStatus.CREATED).build());
    }

    @GetMapping("/{enquiryId}/quotes/{quoteId}/pdf")
    public Mono<ResponseEntity<byte[]>> downloadQuotePdf(
            @PathVariable UUID enquiryId, @PathVariable UUID quoteId,
            @AuthenticationPrincipal CustomUserDetails user) {
        return quoteService.generateQuotePdf(enquiryId, quoteId, user.getUserId(), true)
                .map(bytes -> ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_PDF)
                        .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"quote-" + quoteId + ".pdf\"")
                        .body(bytes));
    }

    // ── Quotes ──────────────────────────────────────────────

    @PostMapping("/{id}/quotes")
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN','MANAGER','OPERATOR')")
    public Mono<ResponseEntity<QuoteResponse>> createQuote(
            @PathVariable UUID id, @Valid @RequestBody CreateQuoteRequest req,
            @AuthenticationPrincipal CustomUserDetails user) {
        return quoteService.createQuote(id, user.getUserId(), req)
                .map(q -> ResponseEntity.status(HttpStatus.CREATED).body(q));
    }

    @PostMapping("/{id}/quotes/{quoteId}/send")
    public Mono<QuoteResponse> sendQuote(
            @PathVariable UUID id, @PathVariable UUID quoteId,
            @AuthenticationPrincipal CustomUserDetails user) {
        return quoteService.sendQuote(id, quoteId, user.getUserId());
    }

    // ── Staff queues ────────────────────────────────────────

    @GetMapping("/queue/unassigned")
    public Mono<Page<EnquirySummaryResponse>> unassigned(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size) {
        return lifecycleService.unassignedQueue(PageRequest.of(page, Math.min(size, 100)));
    }

    @GetMapping("/queue/overdue-followup")
    public Mono<Page<EnquirySummaryResponse>> overdueFollowUp(
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size) {
        return lifecycleService.overdueFollowUpQueue(PageRequest.of(page, Math.min(size, 100)));
    }

    @GetMapping("/queue/departures-upcoming")
    public Mono<Page<EnquirySummaryResponse>> upcomingDepartures(
            @RequestParam(defaultValue = "14") int days,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size) {
        return lifecycleService.upcomingDeparturesQueue(days, PageRequest.of(page, Math.min(size, 100)));
    }


}