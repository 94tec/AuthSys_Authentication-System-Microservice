package com.techStack.authSys.tour.services;

import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.tour.dto.request.*;
import com.techStack.authSys.tour.dto.response.*;
import com.techStack.authSys.tour.models.*;
import com.techStack.authSys.tour.notification.EnquiryNotificationService;
import com.techStack.authSys.tour.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EnquiryLifecycleService {

    private final TourEnquiryRepository enquiryRepository;
    private final EnquiryQuoteRepository quoteRepository;
    private final EnquiryEventRepository eventRepository;
    private final BookingRepository bookingRepository;
    private final EnquiryActivityService activityService;
    private final EnquiryOwnershipGuard ownershipGuard;
    private final EnquiryStatusTransitions transitions;
    private final EnquiryNotificationService notificationService;
    private final TransactionTemplate transactionTemplate;

    // ── Admin: search / dashboard ──────────────────────────

    public Mono<Page<EnquirySummaryResponse>> search(
            TourEnquiryStatus status, String assignedTo, UUID tourId, String search, Pageable pageable) {
        return Mono.fromCallable(() -> enquiryRepository
                        .search(status, assignedTo, tourId, search, pageable)
                        .map(this::toSummary))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<EnquiryDetailResponse> getDetail(UUID enquiryId) {
        return Mono.fromCallable(() -> {
            TourEnquiry e = ownershipGuard.mustFind(enquiryId);
            List<QuoteResponse> quotes = quoteRepository
                    .findAllByEnquiryIdOrderByCreatedDateDesc(enquiryId)
                    .stream().map(this::toQuoteResponse).toList();
            List<ActivityLogResponse> activity = eventRepository
                    .findAllByEnquiryIdOrderByCreatedAtDesc(enquiryId)
                    .stream().map(this::toActivityResponse).toList();
            return toDetail(e, quotes, activity);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<EnquiryDashboardSummary> dashboardSummary() {
        return Mono.fromCallable(() -> new EnquiryDashboardSummary(
                        enquiryRepository.countByStatus(TourEnquiryStatus.NEW),
                        enquiryRepository.countByStatus(TourEnquiryStatus.CONTACTED),
                        enquiryRepository.countByStatus(TourEnquiryStatus.QUOTED),
                        enquiryRepository.countByStatus(TourEnquiryStatus.CONVERTED),
                        enquiryRepository.countByStatus(TourEnquiryStatus.COMPLETED),
                        enquiryRepository.countByStatus(TourEnquiryStatus.LOST),
                        enquiryRepository.countByStatusAndAssignedToIsNull(TourEnquiryStatus.NEW),
                        enquiryRepository.findOverdueFollowUp(
                                List.of(TourEnquiryStatus.CONTACTED, TourEnquiryStatus.QUOTED),
                                Instant.now().minus(java.time.Duration.ofHours(48)),
                                Pageable.unpaged()).getTotalElements(),
                        enquiryRepository.findUpcomingDepartures(
                                LocalDate.now(), LocalDate.now().plusDays(14),
                                Pageable.unpaged()).getTotalElements(),
                        enquiryRepository.findEligibleForAppreciation(LocalDate.now()).size()
                ))
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ── Admin: status / assignment ─────────────────────────

    public Mono<EnquiryDetailResponse> updateStatus(UUID enquiryId, String adminId, UpdateEnquiryStatusRequest req) {
        record StatusChange(TourEnquiry enquiry, String tourName) {}

        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    TourEnquiry e = ownershipGuard.mustFind(enquiryId);
                    TourEnquiryStatus from = e.getStatus();
                    transitions.assertAllowed(from, req.status());

                    e.setStatus(req.status());
                    if (req.status() == TourEnquiryStatus.CONTACTED && e.getFirstContactedAt() == null) {
                        e.setFirstContactedAt(Instant.now());
                    }
                    enquiryRepository.save(e);

                    String tourName = e.getTour().getName();

                    activityService.log(e, ActorType.ADMIN, adminId, ActivityAction.STATUS_CHANGED,
                            from, req.status(), req.note());
                    return new StatusChange(e, tourName);
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(change -> withNotificationSideEffects(change.enquiry(), change.tourName()));
    }

    public Mono<Void> assign(UUID enquiryId, String adminId, AssignEnquiryRequest req) {
        return Mono.fromRunnable(() -> transactionTemplate.executeWithoutResult(status -> {
                    TourEnquiry e = ownershipGuard.mustFind(enquiryId);
                    e.setAssignedTo(req.staffId());
                    enquiryRepository.save(e);
                    activityService.log(e, ActorType.ADMIN, adminId, ActivityAction.ASSIGNED,
                            null, null, "Assigned to staff " + req.staffId());
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    public Mono<Void> addNote(UUID enquiryId, String adminId, String note) {
        return Mono.fromRunnable(() -> transactionTemplate.executeWithoutResult(status -> {
                    TourEnquiry e = ownershipGuard.mustFind(enquiryId);
                    activityService.log(e, ActorType.ADMIN, adminId, ActivityAction.NOTE_ADDED,
                            null, null, note);
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .then();
    }
    // ── Customer: self-service ──────────────────────────────

    public Mono<Page<EnquirySummaryResponse>> myEnquiries(String customerId, TourEnquiryStatus status, Pageable pageable) {
        return Mono.fromCallable(() -> {
                    Page<TourEnquiry> page = (status == null)
                            ? enquiryRepository.findAllByUserIdAndDeletedFalse(customerId, pageable)
                            : enquiryRepository.findAllByUserIdAndStatusAndDeletedFalse(customerId, status, pageable);
                    return page.map(this::toSummary);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /** Customer detail view — same shape as admin but strips internal-only content. */
    public Mono<EnquiryDetailResponse> getMyDetail(UUID enquiryId, String customerId) {
        return Mono.fromCallable(() -> {
                    TourEnquiry e = ownershipGuard.mustFindOwnedBy(enquiryId, customerId);

                    List<QuoteResponse> quotes = quoteRepository
                            .findAllByEnquiryIdOrderByCreatedDateDesc(enquiryId)
                            .stream()
                            // Customers only ever see quotes once sent — a DRAFT is internal.
                            .filter(q -> q.getStatus() != QuoteStatus.DRAFT)
                            .map(this::toQuoteResponse)
                            .toList();
                    List<ActivityLogResponse> activity = eventRepository
                            .findAllByEnquiryIdOrderByCreatedAtDesc(enquiryId)
                            .stream()
                            // Hide internal admin notes/assignment chatter from the customer feed.
                            .filter(a -> a.getActorType() != ActorType.ADMIN
                                    || a.getEventType() == ActivityAction.STATUS_CHANGED
                                    || a.getEventType() == ActivityAction.QUOTE_SENT)
                            .map(this::toActivityResponse)
                            .toList();

                    return toDetail(e, quotes, activity);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }


    // ── Staff queues ────────────────────────────────────────

    public Mono<Page<EnquirySummaryResponse>> unassignedQueue(Pageable pageable) {
        return Mono.fromCallable(() -> enquiryRepository
                        .findAllByStatusAndAssignedToIsNullAndDeletedFalse(TourEnquiryStatus.NEW, pageable)
                        .map(this::toSummary))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Page<EnquirySummaryResponse>> overdueFollowUpQueue(Pageable pageable) {
        return Mono.fromCallable(() -> enquiryRepository
                        .findOverdueFollowUp(
                                List.of(TourEnquiryStatus.CONTACTED, TourEnquiryStatus.QUOTED),
                                Instant.now().minus(java.time.Duration.ofHours(48)),
                                pageable)
                        .map(this::toSummary))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<Page<EnquirySummaryResponse>> upcomingDeparturesQueue(int days, Pageable pageable) {
        return Mono.fromCallable(() -> enquiryRepository
                        .findUpcomingDepartures(LocalDate.now(), LocalDate.now().plusDays(days), pageable)
                        .map(this::toSummary))
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ── Helpers ─────────────────────────────────────────────
    private Mono<EnquiryDetailResponse> withNotificationSideEffects(TourEnquiry e, String tourName) {
        // Fire-and-forget, matches existing pattern; notification service swallows errors.
        Mono<Void> notify = switch (e.getStatus()) {
            case QUOTED -> Mono.empty(); // handled at quote-send time, not here
            case CONVERTED -> notificationService.sendBookingConfirmed(e, tourName);
            case LOST -> notificationService.sendFollowUpClosed(e, tourName);
            default -> Mono.empty();
        };
        return notify.then(getDetail(e.getId()));
    }

    private EnquirySummaryResponse toSummary(TourEnquiry e) {
        return new EnquirySummaryResponse(
                e.getId(), e.getTour().getId(), e.getTour().getName(),
                e.getFullName(), e.getEmail(), e.getStatus(), e.getAssignedTo(),
                e.getCreatedDate(), e.getLastModifiedDate());
    }

    private EnquiryDetailResponse toDetail(TourEnquiry e, List<QuoteResponse> quotes, List<ActivityLogResponse> activity) {
        BigDecimal bookingTotalPrice = null;
        BigDecimal bookingAmountPaid = null;
        BigDecimal bookingBalanceAmount = null;
        String bookingPaymentStatus = null;

        if (e.getBookingReference() != null) {
            Booking booking = bookingRepository
                    .findByBookingReferenceAndDeletedFalse(e.getBookingReference())
                    .orElse(null);

            if (booking != null) {
                bookingTotalPrice = booking.getTotalPrice();
                bookingAmountPaid = booking.getAmountPaid();
                bookingBalanceAmount = booking.getBalanceAmount();
                bookingPaymentStatus = booking.getPaymentStatus().name();
            }
            // booking == null here would mean the enquiry references a booking
            // that no longer exists — shouldn't happen since bookings are
            // soft-deleted, not hard-deleted, but if it ever does, the detail
            // response just omits the balance fields rather than failing the
            // whole request.
        }

        return new EnquiryDetailResponse(
                e.getId(), e.getTour().getId(), e.getTour().getName(),
                e.getFullName(), e.getEmail(), e.getPhone(),
                e.getPreferredContact(), e.getPreferredDate(), e.getFlexibleDates(),
                e.getGroupSizeAdults(), e.getGroupSizeChildren(),
                e.getBudgetRange(), e.getRequirements(),
                e.getStatus(), e.getAssignedTo(),
                e.getTravelStartDate(), e.getTravelEndDate(),
                e.getBookingReference(), e.getAppreciationSentAt(),
                quotes, activity, e.getCreatedDate(), e.getLastModifiedDate(),
                bookingTotalPrice, bookingAmountPaid, bookingBalanceAmount, bookingPaymentStatus
        );
    }

    private QuoteResponse toQuoteResponse(EnquiryQuote q) {
        return new QuoteResponse(
                q.getId(), q.getEnquiry().getId(),q.getAdultCount(),q.getChildCount(),
                q.getPricePerAdult(), q.getPricePerChild(), q.getTotalPrice(),
                q.getCurrency(), q.getValidUntil(), q.getInclusionsNote(),
                q.getStatus(), q.getSentAt(), q.getRespondedAt());
    }

    private ActivityLogResponse toActivityResponse(EnquiryEvent e) {
        return new ActivityLogResponse(
                e.getId(), e.getActorType(), e.getActorId(), e.getEventType(),
                e.getFromStatus(), e.getToStatus(), e.getDetails(), e.getCreatedAt());
    }
}
