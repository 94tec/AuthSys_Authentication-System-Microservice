package com.techStack.authSys.customer.service;

import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.customer.dto.request.AddTravelDocumentRequest;
import com.techStack.authSys.customer.dto.request.UpdateProfileRequest;
import com.techStack.authSys.customer.dto.request.UpdateTravelDocumentRequest;
import com.techStack.authSys.customer.dto.response.*;
import com.techStack.authSys.customer.mapper.CustomerMapper;
import com.techStack.authSys.customer.models.CustomerProfile;
import com.techStack.authSys.customer.models.TravelDocument;
import com.techStack.authSys.customer.repository.CustomerProfileRepository;
import com.techStack.authSys.customer.repository.TravelDocumentRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.UUID;

/**
 * CustomerService — manages the CustomerProfile lifecycle.
 *
 * Profile creation is dual-path: CustomerProfileCreationListener creates it
 * eagerly at registration for USER-role accounts, and getOrCreateProfile()
 * below is the lazy fallback (also handles pre-existing accounts from
 * before the listener existed, and re-creates a profile if it was ever
 * hard-deleted). getOrCreateProfile() tolerates losing the creation race
 * to the listener — see createProfile() below.
 *
 * Transaction management: this service's underlying work is JPA/PostgreSQL,
 * but its public methods return Mono/Flux. @Transactional on a reactive-
 * returning method makes Spring look for a ReactiveTransactionManager —
 * and the only one in this app context is ReactiveFirestoreTransactionManager,
 * which has nothing to do with this service's JPA calls. That mismatch
 * silently opened a Firestore transaction around blocking JPA work running
 * on a different thread (via subscribeOn(boundedElastic())), which then
 * rolled back on every call since the JPA writes were invisible to it.
 *
 * Fix: no @Transactional here. Each blocking body runs inside an explicit
 * TransactionTemplate bound to the JPA PlatformTransactionManager
 * (autoconfigured by Spring Boot — resolved unambiguously by type since
 * ReactiveFirestoreTransactionManager does not implement PlatformTransactionManager).
 *
 * Sections:
 *   PROFILE  — get/create, update, admin read
 *   WISHLIST — add/remove enquire-button.tsx, get list
 *   DOCUMENTS— add, update, delete, set primary
 *   STATS    — admin counts
 *
 * Threading: Mono.fromCallable(() -> txTemplate.execute(...)).subscribeOn(Schedulers.boundedElastic())
 * pattern throughout, consistent with TourService, BookingService, PaymentService.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomerService {

    private final CustomerProfileRepository profileRepository;
    private final TravelDocumentRepository  documentRepository;
    private final CustomerMapper            customerMapper;
    private final PlatformTransactionManager jpaTransactionManager;

    private TransactionTemplate txTemplate;

    @PostConstruct
    private void initTxTemplate() {
        this.txTemplate = new TransactionTemplate(jpaTransactionManager);
    }

    // ── PROFILE ───────────────────────────────────────────────────────────────

    /**
     * Get the customer's profile, creating it if it doesn't yet exist.
     *
     * Called on GET /api/customers/me — first-visit creates a minimal profile
     * from the auth principal data (firstName, lastName, email come from the
     * User entity, not a display-name split — see CustomerController).
     *
     * Also syncs firstName/lastName/email into an existing profile if they've
     * drifted from the auth system (e.g. the user changed their name) —
     * folds in what syncFromAuth() used to do as a separate, uncalled method.
     *
     * Race with CustomerProfileCreationListener: that listener creates
     * profiles eagerly and asynchronously right after registration. If this
     * method runs concurrently (customer hits /me before the listener's
     * write lands), both paths can pass findByCustomerId() as empty and
     * both attempt save() — the loser hits the unique constraint on
     * customer_id. createProfile() below catches that and re-fetches
     * instead of surfacing a 500 on the customer's very first profile visit.
     *
     * @param customerId   Firebase UID
     * @param firstName    from the User entity (CustomUserDetails.getUser())
     * @param lastName     from the User entity
     * @param email        from the User entity
     */
    public Mono<CustomerProfileResponse> getOrCreateProfile(
            String customerId, String firstName, String lastName, String email) {

        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = profileRepository
                    .findByCustomerId(customerId)
                    .map(existing -> syncIfChanged(existing, firstName, lastName, email))
                    .orElseGet(() -> createProfile(customerId, firstName, lastName, email));

            return customerMapper.toProfileResponse(profile);

        })).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Creates a new profile, tolerating a concurrent creation from the
     * eager CustomerProfileCreationListener (or another simultaneous
     * request) racing to insert the same customer_id first.
     */
    private CustomerProfile createProfile(
            String customerId, String firstName, String lastName, String email) {
        try {
            CustomerProfile newProfile = CustomerProfile.builder()
                    .customerId(customerId)
                    .firstName(firstName)
                    .lastName(lastName)
                    .email(email)
                    .build();
            CustomerProfile saved = profileRepository.save(newProfile);
            log.info("Customer profile created: customerId={} email={}",
                    customerId, email);
            return saved;
        } catch (DataIntegrityViolationException e) {
            log.debug("Concurrent profile creation for customerId={} — " +
                    "another writer (likely CustomerProfileCreationListener) won the race, re-fetching", customerId);
            return profileRepository.findByCustomerId(customerId)
                    .orElseThrow(() -> e);
        }
    }

    /**
     * Syncs firstName/lastName/email into a profile if they've drifted from
     * the auth system. No-op (and no extra write) if nothing changed.
     */
    private CustomerProfile syncIfChanged(
            CustomerProfile profile, String firstName, String lastName, String email) {
        boolean changed = false;
        if (firstName != null && !firstName.equals(profile.getFirstName())) {
            profile.setFirstName(firstName); changed = true;
        }
        if (lastName != null && !lastName.equals(profile.getLastName())) {
            profile.setLastName(lastName); changed = true;
        }
        if (email != null && !email.equals(profile.getEmail())) {
            profile.setEmail(email); changed = true;
        }
        if (!changed) {
            return profile;
        }
        CustomerProfile saved = profileRepository.save(profile);
        log.debug("Profile synced from auth: customerId={}", profile.getCustomerId());
        return saved;
    }

    /**
     * Update the authenticated customer's own profile.
     * Patch semantics — only non-null fields applied.
     */
    public Mono<CustomerProfileResponse> updateProfile(
            String customerId, UpdateProfileRequest req) {

        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = loadProfile(customerId);

            if (req.phoneNumber()        != null) profile.setPhoneNumber(req.phoneNumber());
            if (req.bio()                != null) profile.setBio(req.bio());
            if (req.country()            != null) profile.setCountry(req.country());
            if (req.photoUrl()           != null) profile.setPhotoUrl(req.photoUrl());
            if (req.dateOfBirth()        != null) profile.setDateOfBirth(req.dateOfBirth());
            if (req.nationality()        != null) profile.setNationality(req.nationality());
            if (req.dietaryNotes()       != null) profile.setDietaryNotes(req.dietaryNotes());
            if (req.emailMarketingOptIn()!= null) profile.setEmailMarketingOptIn(req.emailMarketingOptIn());
            if (req.smsOptIn()           != null) profile.setSmsOptIn(req.smsOptIn());

            CustomerProfile saved = profileRepository.save(profile);
            log.info("Profile updated: customerId={}", customerId);
            return customerMapper.toProfileResponse(saved);

        })).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Sync firstName/lastName/email from the auth system into the profile.
     * Kept as a standalone entry point for callers outside the /me flow
     * (e.g. a future login event listener) — getOrCreateProfile() now does
     * this same sync inline on every /me call, so this is no longer the
     * only place it happens.
     * No-op if the profile doesn't exist yet (lazy creation handles it).
     */
    public Mono<Void> syncFromAuth(
            String customerId, String firstName, String lastName, String email) {

        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            profileRepository.findByCustomerIdAndDeletedFalse(customerId)
                    .ifPresent(profile -> syncIfChanged(profile, firstName, lastName, email));
            return null;
        })).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // ── STAFF / ADMIN reads ───────────────────────────────────────────────────

    /**
     * Get any customer's profile by internal profile UUID — staff use.
     * Accessible to MANAGER, ADMIN, SUPER_ADMIN.
     * Read-only — no transaction template needed.
     */
    public Mono<CustomerProfileResponse> getProfileById(UUID profileId) {
        return Mono.fromCallable(() -> {
            CustomerProfile profile = profileRepository
                    .findByIdAndDeletedFalse(profileId)
                    .orElseThrow(() -> new ResourceNotFoundException(
                            HttpStatus.NOT_FOUND, "Customer profile not found: " + profileId));
            return customerMapper.toProfileResponse(profile);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Paginated list of all customers — ADMIN view.
     * Read-only — no transaction template needed.
     */
    public Mono<Page<CustomerSummaryResponse>> getAllCustomers(int page, int size) {
        return Mono.fromCallable(() -> {
            PageRequest pageable = PageRequest.of(
                    page, size, Sort.by("createdDate").descending());
            return profileRepository.findAllByDeletedFalse(pageable)
                    .map(customerMapper::toSummaryResponse);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Search customers by name or email — staff customer lookup.
     * Read-only — no transaction template needed.
     */
    public Mono<Page<CustomerSummaryResponse>> searchCustomers(
            String query, int page, int size) {

        return Mono.fromCallable(() -> {
            PageRequest pageable = PageRequest.of(page, size,
                    Sort.by("lastName").ascending());
            return profileRepository
                    .searchByEmailOrName(query.trim(), pageable)
                    .map(customerMapper::toSummaryResponse);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Total customer count — admin dashboard stat.
     * Read-only — no transaction template needed.
     */
    public Mono<Long> countCustomers() {
        return Mono.fromCallable(profileRepository::countByDeletedFalse)
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ── WISHLIST ──────────────────────────────────────────────────────────────

    /**
     * Get the customer's saved enquire-button.tsx IDs.
     * Read-only — no transaction template needed.
     */
    public Mono<WishlistResponse> getWishlist(String customerId) {
        return Mono.fromCallable(() -> {
            CustomerProfile profile = loadProfile(customerId);
            return WishlistResponse.builder()
                    .tourIds(profile.getSavedTourIds())
                    .count(profile.getSavedTourIds().size())
                    .build();
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Add a enquire-button.tsx to the customer's wishlist.
     * Idempotent — no error if already saved.
     */
    public Mono<WishlistResponse> addToWishlist(String customerId, UUID tourId) {
        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = loadProfile(customerId);
            profile.addToWishlist(tourId);
            profileRepository.save(profile);
            log.debug("Tour {} added to wishlist for customer {}", tourId, customerId);
            return WishlistResponse.builder()
                    .tourIds(profile.getSavedTourIds())
                    .count(profile.getSavedTourIds().size())
                    .build();
        })).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Remove a enquire-button.tsx from the customer's wishlist.
     * No-op if the enquire-button.tsx was not in the wishlist.
     */
    public Mono<WishlistResponse> removeFromWishlist(String customerId, UUID tourId) {
        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = loadProfile(customerId);
            profile.removeFromWishlist(tourId);
            profileRepository.save(profile);
            return WishlistResponse.builder()
                    .tourIds(profile.getSavedTourIds())
                    .count(profile.getSavedTourIds().size())
                    .build();
        })).subscribeOn(Schedulers.boundedElastic());
    }

    // ── TRAVEL DOCUMENTS ──────────────────────────────────────────────────────

    /**
     * List all saved travel documents for the authenticated customer.
     * Read-only — no transaction template needed.
     */
    public Flux<TravelDocumentResponse> getDocuments(String customerId) {
        return Mono.fromCallable(() -> {
                    CustomerProfile profile = loadProfile(customerId);
                    return documentRepository
                            .findByCustomerProfileIdAndDeletedFalse(profile.getId())
                            .stream()
                            .map(customerMapper::toDocumentResponse)
                            .toList();
                }).subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(Flux::fromIterable);
    }

    /**
     * Add a new travel document to the customer's profile.
     * If primaryDocument = true, clears the flag on all other documents first.
     */
    public Mono<TravelDocumentResponse> addDocument(
            String customerId, AddTravelDocumentRequest req) {

        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = loadProfile(customerId);

            // Enforce single primary per customer
            if (req.primaryDocument()) {
                documentRepository.clearPrimaryForProfile(profile.getId());
            }

            TravelDocument doc = TravelDocument.builder()
                    .customerProfile(profile)
                    .documentType(req.documentType())
                    .fullName(req.fullName())
                    .documentNumber(req.documentNumber())
                    .nationality(req.nationality())
                    .issuingCountry(req.issuingCountry())
                    .dateOfBirth(req.dateOfBirth())
                    .expiryDate(req.expiryDate())
                    .label(req.label() != null ? req.label()
                            : req.documentType().getDisplayName())
                    .primaryDocument(req.primaryDocument())
                    .build();

            TravelDocument saved = documentRepository.save(doc);
            log.info("Document added: type={} customer={}",
                    req.documentType(), customerId);
            return customerMapper.toDocumentResponse(saved);

        })).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Patch a saved travel document.
     * Scoped to the customer — IDOR guard via findByIdAndCustomerProfileId.
     */
    public Mono<TravelDocumentResponse> updateDocument(
            String customerId, UUID documentId, UpdateTravelDocumentRequest req) {

        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = loadProfile(customerId);
            TravelDocument doc = loadDocument(documentId, profile.getId());

            if (req.fullName()       != null) doc.setFullName(req.fullName());
            if (req.nationality()    != null) doc.setNationality(req.nationality());
            if (req.issuingCountry() != null) doc.setIssuingCountry(req.issuingCountry());
            if (req.dateOfBirth()    != null) doc.setDateOfBirth(req.dateOfBirth());
            if (req.expiryDate()     != null) doc.setExpiryDate(req.expiryDate());
            if (req.label()          != null) doc.setLabel(req.label());

            TravelDocument saved = documentRepository.save(doc);
            return customerMapper.toDocumentResponse(saved);

        })).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Set a document as the primary/default.
     * Clears the flag on all other documents for this customer first.
     */
    public Mono<TravelDocumentResponse> setPrimaryDocument(
            String customerId, UUID documentId) {

        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = loadProfile(customerId);
            TravelDocument doc = loadDocument(documentId, profile.getId());

            documentRepository.clearPrimaryForProfile(profile.getId());
            doc.setPrimaryDocument(true);
            TravelDocument saved = documentRepository.save(doc);

            log.info("Primary document set: docId={} customer={}", documentId, customerId);
            return customerMapper.toDocumentResponse(saved);

        })).subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Soft-delete a travel document.
     * Scoped to the customer — cannot delete another customer's document.
     */
    public Mono<Void> deleteDocument(String customerId, UUID documentId) {
        return Mono.fromCallable(() -> txTemplate.execute(status -> {
            CustomerProfile profile = loadProfile(customerId);
            TravelDocument doc = loadDocument(documentId, profile.getId());
            doc.setDeleted(true);
            documentRepository.save(doc);
            log.info("Document deleted: docId={} customer={}", documentId, customerId);
            return null;
        })).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Load a non-deleted profile by Firebase UID.
     * Throws 404 if not found — callers that need lazy creation use getOrCreateProfile().
     */
    private CustomerProfile loadProfile(String customerId) {
        return profileRepository
                .findByCustomerIdAndDeletedFalse(customerId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "Customer profile not found. Please visit /api/customers/me first."));
    }

    /**
     * Load a non-deleted document scoped to a profile — IDOR guard.
     */
    private TravelDocument loadDocument(UUID documentId, UUID profileId) {
        return documentRepository
                .findByIdAndCustomerProfileIdAndDeletedFalse(documentId, profileId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "Travel document not found: " + documentId));
    }
}