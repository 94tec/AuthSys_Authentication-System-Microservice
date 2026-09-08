package com.techStack.authSys.tour.services;

import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.security.exception.RateLimitExceededException;
import com.techStack.authSys.tour.dto.request.CreateEnquiryRequest;
import com.techStack.authSys.tour.dto.response.EnquiryResponse;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourEnquiry;
import com.techStack.authSys.tour.notification.EnquiryNotificationService;
import com.techStack.authSys.tour.repository.TourEnquiryRepository;
import com.techStack.authSys.tour.repository.TourRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TourEnquiryService {

    private static final int DUPLICATE_WINDOW_HOURS = 24;

    private final TourEnquiryRepository enquiryRepository;
    private final TourRepository tourRepository;
    private final EnquiryNotificationService notificationService;
    private final TransactionTemplate transactionTemplate;

    public Mono<EnquiryResponse> createEnquiry(UUID tourId,
                                               String authenticatedUserId,
                                               CreateEnquiryRequest request) {
        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    Tour tour = tourRepository.findByIdAndDeletedFalse(tourId)
                            .orElseThrow(() -> new ResourceNotFoundException(
                                    HttpStatus.NOT_FOUND, "Tour not found: " + tourId));

                    Instant cutoff = Instant.now().minus(DUPLICATE_WINDOW_HOURS, ChronoUnit.HOURS);
                    boolean duplicate = enquiryRepository
                            .existsByTourIdAndUserIdAndCreatedDateAfter(tourId, authenticatedUserId, cutoff);
                    if (duplicate) {
                        throw RateLimitExceededException.duplicateEnquiry();
                    }

                    TourEnquiry enquiry = TourEnquiry.builder()
                            .tour(tour)
                            .userId(authenticatedUserId)
                            .fullName(request.fullName())
                            .email(request.email())
                            .phone(request.phone())
                            .preferredContact(request.preferredContact())
                            .preferredDate(request.preferredDate())
                            .flexibleDates(Boolean.TRUE.equals(request.flexibleDates()))
                            .groupSizeAdults(request.groupSizeAdults())
                            .groupSizeChildren(request.groupSizeChildren())
                            .budgetRange(request.budgetRange())
                            .requirements(request.requirements())
                            .source(request.source())
                            .consent(request.consent() == null || request.consent())
                            .build();

                    TourEnquiry saved = enquiryRepository.save(enquiry);
                    log.info("Enquiry {} created for tour {} by user {}",
                            saved.getId(), tourId, authenticatedUserId);

                    // Snapshot the tour name now; `tour` may be a lazy proxy after tx ends.
                    return new CreatedEnquiry(saved, tour.getName(), toResponse(saved, tour));
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(created -> {
                    // Fire-and-forget: the notification service already swallows errors.
                    Mono<Void> lead = notificationService.sendLeadNotification(
                            created.enquiry(), created.tourName());
                    Mono<Void> reply = notificationService.sendAutoReply(
                            created.enquiry(), created.tourName());
                    return Mono.when(lead, reply).thenReturn(created.response());
                });
    }

    public Mono<Page<EnquiryResponse>> listForTour(UUID tourId, Pageable pageable) {
        return Mono.fromCallable(() ->
                        enquiryRepository.findAllByTourIdAndDeletedFalse(tourId, pageable)
                                .map(e -> toResponse(e, e.getTour()))
                )
                .subscribeOn(Schedulers.boundedElastic());
    }

    private EnquiryResponse toResponse(TourEnquiry e, Tour tour) {
        return new EnquiryResponse(
                e.getId(), tour.getId(), tour.getName(),
                e.getFullName(), e.getEmail(), e.getPhone(),
                e.getPreferredContact(), e.getPreferredDate(),
                e.getGroupSizeAdults(), e.getGroupSizeChildren(),
                e.getBudgetRange(), e.getRequirements(),
                e.getStatus(), e.getCreatedDate(), e.getLastModifiedDate()
        );
    }

    /** Carries just enough out of the transaction to fire notifications safely. */
    private record CreatedEnquiry(TourEnquiry enquiry, String tourName, EnquiryResponse response) {}
}