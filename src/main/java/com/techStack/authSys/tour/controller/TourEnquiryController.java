package com.techStack.authSys.tour.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.tour.dto.request.CreateEnquiryRequest;
import com.techStack.authSys.tour.dto.response.EnquiryResponse;
import com.techStack.authSys.tour.services.TourEnquiryService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/api/tours/{tourId}/enquiries")
@RequiredArgsConstructor
public class TourEnquiryController {

    private final TourEnquiryService enquiryService;

    @PostMapping
    @PreAuthorize("isAuthenticated()")
    public Mono<ResponseEntity<EnquiryResponse>> create(
            @PathVariable UUID tourId,
            @Valid @RequestBody CreateEnquiryRequest request,
            @AuthenticationPrincipal CustomUserDetails user) {

        return enquiryService.createEnquiry(tourId, user.getUserId(), request)
                .map(res -> ResponseEntity.status(HttpStatus.CREATED).body(res));
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SUPER_ADMIN','MANAGER','OPERATOR')")
    public Mono<ResponseEntity<?>> listForTour(
            @PathVariable UUID tourId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return enquiryService.listForTour(tourId, PageRequest.of(page, Math.min(size, 100)))
                .map(ResponseEntity::ok);
    }
}