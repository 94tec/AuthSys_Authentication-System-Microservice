package com.techStack.authSys.tour.services;

import com.techStack.authSys.common.exception.CustomException;
import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.tour.dto.pdf.QuotePdfData;
import com.techStack.authSys.tour.dto.request.CreateQuoteRequest;
import com.techStack.authSys.tour.dto.response.QuoteResponse;
import com.techStack.authSys.tour.exception.QuoteExpiredException;
import com.techStack.authSys.tour.exception.QuoteStatusException;
import com.techStack.authSys.tour.models.*;
import com.techStack.authSys.tour.notification.EnquiryNotificationService;
import com.techStack.authSys.tour.repository.EnquiryQuoteRepository;
import com.techStack.authSys.tour.repository.TourEnquiryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EnquiryQuoteService {

    private final EnquiryQuoteRepository quoteRepository;
    private final TourEnquiryRepository enquiryRepository;
    private final EnquiryActivityService activityService;
    private final EnquiryOwnershipGuard ownershipGuard;
    private final QuoteStatusTransitions quoteTransitions;
    //private final EnquiryStatusTransitions transitions;
    private final EnquiryNotificationService notificationService;
    private final TransactionTemplate transactionTemplate;

    private final QuotePdfService quotePdfService;

    @Value("${app.frontend-base-url}")
    private String frontendBaseUrl;

    /**
     * Admin creates a DRAFT quote.
     *
     * Pricing is calculated on the backend.
     * The frontend never supplies the authoritative total.
     */
    public Mono<QuoteResponse> createQuote(
            UUID enquiryId,
            String adminId,
            CreateQuoteRequest req
    ) {
        return Mono.fromCallable(() ->
                        transactionTemplate.execute(status -> {

                            TourEnquiry enquiry =
                                    ownershipGuard.mustFind(enquiryId);

                            validatePricingRequest(req);

                            BigDecimal totalPrice =
                                    calculateTotalPrice(req);

                            EnquiryQuote quote =
                                    EnquiryQuote.builder()
                                            .enquiry(enquiry)

                                            .adultCount(req.adultCount())
                                            .childCount(req.childCount())

                                            .pricePerAdult(req.pricePerAdult())
                                            .pricePerChild(req.pricePerChild())

                                            .totalPrice(totalPrice)

                                            .currency(req.currency())
                                            .validUntil(req.validUntil())

                                            .inclusionsNote(
                                                    req.inclusionsNote()
                                            )
                                            .internalNote(
                                                    req.internalNote()
                                            )

                                            .status(QuoteStatus.DRAFT)
                                            .build();

                            quote = quoteRepository.save(quote);

                            activityService.log(
                                    enquiry,
                                    ActorType.ADMIN,
                                    adminId,
                                    ActivityAction.QUOTE_CREATED,
                                    null,
                                    null,
                                    "Quote " + quote.getId()
                                            + " drafted for "
                                            + req.adultCount()
                                            + " adult(s) and "
                                            + req.childCount()
                                            + " child(ren)"
                            );

                            return quote;
                        })
                )
                .subscribeOn(Schedulers.boundedElastic())
                .map(this::toResponse);
    }

    /**
     * Admin sends the quote.
     *
     * This moves the enquiry into QUOTED.
     */
    public Mono<QuoteResponse> sendQuote(
            UUID enquiryId,
            UUID quoteId,
            String adminId
    ) {

        record SentQuote(
                EnquiryQuote quote,
                String tourName,
                PreferredContact channel,
                String phone
        ) {}

        return Mono.fromCallable(() ->
                        transactionTemplate.execute(status -> {

                            TourEnquiry enquiry =
                                    ownershipGuard.mustFind(enquiryId);

                            EnquiryQuote quote =
                                    quoteRepository
                                            .findByIdAndEnquiryId(
                                                    quoteId,
                                                    enquiryId
                                            )
                                            .orElseThrow(() ->
                                                    new ResourceNotFoundException(
                                                            HttpStatus.NOT_FOUND,
                                                            "Quote not found: "
                                                                    + quoteId
                                                    )
                                            );
                            quoteTransitions.assertCanSend(quote);

                            quote.setStatus(QuoteStatus.SENT);
                            quote.setSentAt(Instant.now());

                            quoteRepository.save(quote);

                            TourEnquiryStatus from =
                                    enquiry.getStatus();

                            //transitions.assertAllowed(from, TourEnquiryStatus.QUOTED);

                            enquiry.setStatus(
                                    TourEnquiryStatus.QUOTED
                            );

                            enquiryRepository.save(enquiry);

                            /*
                             * Read the lazy relationship while the
                             * transaction/session is still open.
                             */
                            String tourName =
                                    enquiry.getTour().getName();

                            /*
                             * Snapshot the communication channel before
                             * leaving the transaction.
                             *
                             * If WhatsApp/Phone was preferred but there
                             * is no phone number, fall back to email.
                             */
                            PreferredContact channel =
                                    enquiry.getPreferredContact();

                            String phone =
                                    enquiry.getPhone();

                            if (
                                    channel != PreferredContact.EMAIL
                                            && (phone == null
                                            || phone.isBlank())
                            ) {
                                log.warn(
                                        "Enquiry {} prefers {} but has "
                                                + "no phone on file — "
                                                + "falling back to email",
                                        enquiry.getId(),
                                        channel
                                );

                                channel = PreferredContact.EMAIL;
                            }

                            activityService.log(
                                    enquiry,
                                    ActorType.ADMIN,
                                    adminId,
                                    ActivityAction.QUOTE_SENT,
                                    from,
                                    TourEnquiryStatus.QUOTED,
                                    "Quote "
                                            + quote.getId()
                                            + " sent via "
                                            + channel
                            );

                            return new SentQuote(
                                    quote,
                                    tourName,
                                    channel,
                                    phone
                            );
                        })
                )
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(sent -> {

                    Mono<Void> delivery =
                            switch (sent.channel()) {

                                case EMAIL ->
                                        notificationService
                                                .sendQuoteReady(
                                                        sent.quote(),
                                                        sent.tourName()
                                                );

                                case WHATSAPP, PHONE ->
                                        notificationService
                                                .sendQuoteReadyWhatsApp(
                                                        sent.quote(),
                                                        sent.tourName(),
                                                        sent.phone()
                                                );
                            };

                    return delivery.thenReturn(sent.quote());
                })
                .map(this::toResponse);
    }

    /**
     * Customer accepts a quote.
     *
     * The accepted EnquiryQuote remains the authoritative
     * commercial/pricing snapshot for the enquiry.
     */
    public Mono<QuoteResponse> acceptQuote(
            UUID enquiryId,
            UUID quoteId,
            String customerId
    ) {
        record AcceptedQuote(
                EnquiryQuote quote,
                String tourName
        ) {}

        return Mono.fromCallable(() ->
                        transactionTemplate.execute(status -> {

                            TourEnquiry enquiry =
                                    ownershipGuard.mustFindOwnedBy(
                                            enquiryId,
                                            customerId
                                    );

                            EnquiryQuote quote =
                                    quoteRepository
                                            .findByIdAndEnquiryId(quoteId, enquiryId)
                                            .orElseThrow(() ->
                                                    new ResourceNotFoundException(
                                                            HttpStatus.NOT_FOUND,
                                                            "Quote not found: " + quoteId
                                                    )
                                            );

                            // Centralized lifecycle validation.
                            quoteTransitions.assertCanAccept(quote);

                            // Quote validity validation.
                            if (quote.getValidUntil() == null) {
                                throw new CustomException(
                                        HttpStatus.CONFLICT,
                                        "This quote has no validity date and cannot be accepted."
                                );
                            }

                            if (quote.getValidUntil().isBefore(LocalDate.now())) {
                                throw new QuoteExpiredException(
                                        quote.getId(),
                                        quote.getValidUntil()
                                );
                            }

                            // Accept the commercial snapshot.
                            quote.setStatus(QuoteStatus.ACCEPTED);
                            quote.setRespondedAt(Instant.now());

                            EnquiryQuote savedQuote =
                                    quoteRepository.save(quote);

                            String tourName = enquiry.getTour().getName();

                            activityService.log(
                                    enquiry,
                                    ActorType.CUSTOMER,
                                    customerId,
                                    ActivityAction.QUOTE_ACCEPTED,
                                    null,
                                    null,
                                    "Customer accepted quote "
                                            + savedQuote.getId()
                                            + " and agreed to the payment terms"
                            );

                            return new AcceptedQuote(
                                    savedQuote,
                                    tourName
                            );
                        })
                )
                .subscribeOn(Schedulers.boundedElastic())

                // Notification is intentionally outside the DB transaction.
                .flatMap(accepted ->
                        notificationService
                                .sendQuoteAcceptedPaymentInstructions(
                                        accepted.quote(),
                                        accepted.tourName()
                                )
                                .thenReturn(accepted.quote())
                )

                .map(this::toResponse);
    }

    public Mono<byte[]> generateQuotePdf(UUID enquiryId, UUID quoteId, String requesterId, boolean isAdminRequest) {
        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    TourEnquiry enquiry = isAdminRequest
                            ? ownershipGuard.mustFind(enquiryId)
                            : ownershipGuard.mustFindOwnedBy(enquiryId, requesterId);

                    EnquiryQuote quote = quoteRepository.findByIdAndEnquiryId(quoteId, enquiryId)
                            .orElseThrow(() -> new ResourceNotFoundException(
                                    HttpStatus.NOT_FOUND, "Quote not found: " + quoteId));

                    Tour tour = enquiry.getTour(); // read while session is open

                    return new QuotePdfData(
                            quote.getId().toString(),
                            enquiry.getFullName(),
                            enquiry.getEmail(),
                            tour.getName(),
                            tour.getDestination(),
                            tour.getCountry(),
                            tour.getDurationDays(),
                            tour.getDurationNights(),
                            enquiry.getPreferredDate(),
                            quote.getAdultCount(),
                            quote.getChildCount(),
                            quote.getPricePerAdult(),
                            quote.getPricePerChild(),
                            quote.getTotalPrice(),
                            quote.getCurrency().name(),
                            quote.getValidUntil(),
                            quote.getInclusionsNote(),
                            frontendBaseUrl + "/verify-quote/" + quote.getId()
                    );
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .map(quotePdfService::generate);
    }

    /**
     * Validate quote pricing before calculating the total.
     */
    private void validatePricingRequest(
            CreateQuoteRequest req
    ) {

        if (req.adultCount() == null || req.adultCount() < 0) {
            throw new IllegalArgumentException(
                    "Adult count cannot be negative"
            );
        }

        if (req.childCount() == null || req.childCount() < 0) {
            throw new IllegalArgumentException(
                    "Child count cannot be negative"
            );
        }

        if (
                req.adultCount() == 0
                        && req.childCount() == 0
        ) {
            throw new IllegalArgumentException(
                    "At least one adult or child is required"
            );
        }

        if (req.pricePerAdult() == null
                || req.pricePerAdult().signum() <= 0) {
            throw new IllegalArgumentException(
                    "Adult price must be greater than zero"
            );
        }

        /*
         * A child price is mandatory whenever children
         * are included in the quote.
         */
        if (req.childCount() > 0) {

            if (
                    req.pricePerChild() == null
                            || req.pricePerChild().signum() < 0
            ) {
                throw new IllegalArgumentException(
                        "Child price is required when children are included"
                );
            }
        }
    }

    /**
     * Calculate the authoritative quote total.
     */
    private BigDecimal calculateTotalPrice(
            CreateQuoteRequest req
    ) {

        BigDecimal adultTotal =
                req.pricePerAdult()
                        .multiply(
                                BigDecimal.valueOf(
                                        req.adultCount()
                                )
                        );

        BigDecimal childTotal =
                BigDecimal.ZERO;

        if (req.childCount() > 0) {

            childTotal =
                    req.pricePerChild()
                            .multiply(
                                    BigDecimal.valueOf(
                                            req.childCount()
                                    )
                            );
        }

        return adultTotal.add(childTotal);
    }

    /**
     * Convert the persistence model to the API response.
     */
    private QuoteResponse toResponse(
            EnquiryQuote quote
    ) {

        return new QuoteResponse(
                quote.getId(),
                quote.getEnquiry().getId(),

                quote.getAdultCount(),
                quote.getChildCount(),

                quote.getPricePerAdult(),
                quote.getPricePerChild(),
                quote.getTotalPrice(),

                quote.getCurrency(),
                quote.getValidUntil(),

                quote.getInclusionsNote(),
                quote.getStatus(),

                quote.getSentAt(),
                quote.getRespondedAt()
        );
    }
}

