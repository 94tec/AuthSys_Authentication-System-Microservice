package com.techStack.authSys.customer.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.common.dto.ApiResponse;
import com.techStack.authSys.customer.dto.request.AddTravelDocumentRequest;
import com.techStack.authSys.customer.dto.request.UpdateProfileRequest;
import com.techStack.authSys.customer.dto.request.UpdateTravelDocumentRequest;
import com.techStack.authSys.customer.dto.response.*;
import com.techStack.authSys.customer.service.CustomerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * CustomerController — /api/customers/**
 *
 * USER (authenticated customer):
 *   GET  /api/customers/me                        get/create own profile
 *   PUT  /api/customers/me                        update own profile
 *   GET  /api/customers/me/wishlist               get wishlist
 *   POST /api/customers/me/wishlist/{tourId}      add to wishlist
 *   DELETE /api/customers/me/wishlist/{tourId}    remove from wishlist
 *   GET  /api/customers/me/documents              list saved documents
 *   POST /api/customers/me/documents              add document
 *   PUT  /api/customers/me/documents/{id}         update document
 *   POST /api/customers/me/documents/{id}/primary set primary document
 *   DELETE /api/customers/me/documents/{id}       delete document
 *
 * MANAGER, ADMIN, SUPER_ADMIN (staff):
 *   GET  /api/customers/admin/search?q=           search customers
 *   GET  /api/customers/admin/{id}                get any customer profile
 *
 * ADMIN, SUPER_ADMIN:
 *   GET  /api/customers/admin/all                 paginated all customers
 *   GET  /api/customers/admin/stats/count         total customer count
 */
@Slf4j
@RestController
@RequestMapping("/api/customers")
@RequiredArgsConstructor
@Tag(name = "Customers", description = "Customer profile, wishlist, and travel document management")
public class CustomerController {

    private final CustomerService customerService;

    // ── USER: profile ─────────────────────────────────────────────────────────

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Get own profile — creates it on first visit")
    public Mono<CustomerProfileResponse> getMyProfile(
            @AuthenticationPrincipal CustomUserDetails user) {
        // firstName/lastName come from the User entity itself — same source
        // CustomerProfileCreationListener uses — not a displayName split,
        // which broke on multi-word first names and null displayNames.
        return customerService.getOrCreateProfile(
                user.getUserId(),
                user.getUser().getFirstName(),
                user.getUser().getLastName(),
                user.getUser().getEmail()
        );
    }

    @PutMapping("/me")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Update own profile — patch semantics, null fields ignored")
    public Mono<CustomerProfileResponse> updateMyProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.updateProfile(user.getUserId(), request);
    }

    // ── USER: wishlist ────────────────────────────────────────────────────────

    @GetMapping("/me/wishlist")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Get saved enquire-button.tsx IDs — wishlist")
    public Mono<WishlistResponse> getWishlist(
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.getWishlist(user.getUserId());
    }

    @PostMapping("/me/wishlist/{tourId}")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Add a enquire-button.tsx to wishlist — idempotent")
    public Mono<WishlistResponse> addToWishlist(
            @PathVariable UUID tourId,
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.addToWishlist(user.getUserId(), tourId);
    }

    @DeleteMapping("/me/wishlist/{tourId}")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Remove a enquire-button.tsx from wishlist")
    public Mono<WishlistResponse> removeFromWishlist(
            @PathVariable UUID tourId,
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.removeFromWishlist(user.getUserId(), tourId);
    }

    // ── USER: travel documents ────────────────────────────────────────────────

    @GetMapping("/me/documents")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "List all saved travel documents")
    public Flux<TravelDocumentResponse> getDocuments(
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.getDocuments(user.getUserId());
    }

    @PostMapping("/me/documents")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Save a new travel document (passport, ID, etc.)")
    public Mono<TravelDocumentResponse> addDocument(
            @Valid @RequestBody AddTravelDocumentRequest request,
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.addDocument(user.getUserId(), request);
    }

    @PutMapping("/me/documents/{id}")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Update a saved travel document — patch semantics")
    public Mono<TravelDocumentResponse> updateDocument(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateTravelDocumentRequest request,
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.updateDocument(user.getUserId(), id, request);
    }

    @PostMapping("/me/documents/{id}/primary")
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Set a document as primary — pre-fills booking form")
    public Mono<TravelDocumentResponse> setPrimaryDocument(
            @PathVariable UUID id,
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.setPrimaryDocument(user.getUserId(), id);
    }

    @DeleteMapping("/me/documents/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('USER')")
    @Operation(summary = "Delete a saved travel document")
    public Mono<Void> deleteDocument(
            @PathVariable UUID id,
            @AuthenticationPrincipal CustomUserDetails user) {
        return customerService.deleteDocument(user.getUserId(), id);
    }

    // ── STAFF: search and view ────────────────────────────────────────────────

    @GetMapping("/admin/search")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Search customers by name or email — staff lookup")
    public Mono<Page<CustomerSummaryResponse>> searchCustomers(
            @RequestParam @Parameter(description = "Name or email fragment") String q,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "20") int size) {
        return customerService.searchCustomers(q, page, size);
    }

    @GetMapping("/admin/{profileId}")
    @PreAuthorize("hasAnyRole('MANAGER', 'ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Get any customer profile by ID — staff view")
    public Mono<CustomerProfileResponse> getCustomerById(
            @PathVariable UUID profileId) {
        return customerService.getProfileById(profileId);
    }

    // ── ADMIN: all customers ──────────────────────────────────────────────────

    @GetMapping("/admin/all")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Paginated list of all customers — Admin only")
    public Mono<Page<CustomerSummaryResponse>> getAllCustomers(
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "20") int size) {
        return customerService.getAllCustomers(page, size);
    }

    @GetMapping("/admin/stats/count")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @Operation(summary = "Total registered customer count — dashboard stat")
    public Mono<ResponseEntity<ApiResponse<Long>>> getCustomerCount() {
        return customerService.countCustomers()
                .map(count -> ResponseEntity.ok(
                        new ApiResponse<>(true, "Total customers", count)));
    }
}