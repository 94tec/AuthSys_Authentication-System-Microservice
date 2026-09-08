package com.techStack.authSys.tour.services;

import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.common.exception.CustomException;
import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.tour.dto.request.RejectPaymentRequest;
import com.techStack.authSys.tour.dto.request.SubmitPaymentRequest;
import com.techStack.authSys.tour.dto.response.PaymentSubmissionResponse;
import com.techStack.authSys.tour.models.*;
import com.techStack.authSys.tour.notification.EnquiryNotificationService;
import com.techStack.authSys.tour.repository.EnquiryQuoteRepository;
import com.techStack.authSys.tour.repository.PaymentSubmissionRepository;
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
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PaymentSubmissionService {

    private final PaymentSubmissionRepository paymentSubmissionRepository;
    private final EnquiryQuoteRepository quoteRepository;
    private final BookingRepository bookingRepository;
    private final EnquiryOwnershipGuard ownershipGuard;
    private final EnquiryActivityService activityService;
    private final EnquiryNotificationService notificationService;
    private final TransactionTemplate transactionTemplate;

    /**
     * Customer submits a payment claim. This NEVER marks the payment as
     * verified — it only records the claim and notifies admin. Only
     * verifyPayment() (admin-only) can move a submission to VERIFIED.
     */
    public Mono<PaymentSubmissionResponse> submitPayment(
            UUID enquiryId, UUID quoteId, String customerId, SubmitPaymentRequest req
    ) {
        record Submitted(PaymentSubmission submission, TourEnquiry enquiry, String tourName, boolean isBalance) {}

        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    TourEnquiry enquiry = ownershipGuard.mustFindOwnedBy(enquiryId, customerId);

                    EnquiryQuote quote = quoteRepository.findByIdAndEnquiryId(quoteId, enquiryId)
                            .orElseThrow(() -> new ResourceNotFoundException(
                                    HttpStatus.NOT_FOUND, "Quote not found: " + quoteId));

                    if (quote.getStatus() != QuoteStatus.ACCEPTED) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Payment can only be submitted for an accepted quote. Current status: " + quote.getStatus());
                    }

                    if (paymentSubmissionRepository.existsByQuoteIdAndStatus(
                            quote.getId(), PaymentSubmissionStatus.PENDING_VERIFICATION)) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "A payment submission for this quote is already awaiting verification.");
                    }

                    Booking existingBooking = null;
                    BigDecimal maxAllowed = quote.getTotalPrice();

                    if (enquiry.getBookingReference() != null) {
                        existingBooking = bookingRepository
                                .findByBookingReferenceAndDeletedFalse(enquiry.getBookingReference())
                                .orElseThrow(() -> new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Enquiry references booking " + enquiry.getBookingReference() + " but it wasn't found"));

                        if (existingBooking.getBalanceAmount().signum() <= 0) {
                            throw new CustomException(HttpStatus.BAD_REQUEST, "This booking is already fully paid.");
                        }
                        maxAllowed = existingBooking.getBalanceAmount();
                    }

                    if (req.amountPaid().compareTo(maxAllowed) > 0) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Amount exceeds what's currently due (" + maxAllowed + "). "
                                        + "If you're paying the balance, check the amount and try again.");
                    }

                    PaymentSubmission submission = PaymentSubmission.builder()
                            .quote(quote)
                            .channel(req.channel())
                            .referenceCode(req.referenceCode().trim())
                            .amountPaid(req.amountPaid())
                            .payerName(req.payerName())
                            .relatedBookingId(existingBooking != null ? existingBooking.getId() : null)
                            .relatedBookingReference(existingBooking != null ? existingBooking.getBookingReference() : null)
                            .status(PaymentSubmissionStatus.PENDING_VERIFICATION)
                            .build();

                    submission = paymentSubmissionRepository.save(submission);

                    String tourName = enquiry.getTour().getName();
                    boolean isBalance = existingBooking != null;

                    activityService.log(
                            enquiry, ActorType.CUSTOMER, customerId,
                            ActivityAction.PAYMENT_SUBMITTED, null, null,
                            (isBalance ? "Balance payment" : "Payment") + " claim submitted, ref "
                                    + req.referenceCode() + " for " + req.amountPaid()
                    );

                    return new Submitted(submission, enquiry, tourName, isBalance);
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(result -> notificationService
                        .sendPaymentSubmittedAdminAlert(result.submission(), result.enquiry(), result.tourName(), result.isBalance())
                        .thenReturn(result.submission()))
                .map(this::toResponse);
    }

    /** Admin lists all pending payment claims — the verification queue. */
    public Mono<Page<PaymentSubmissionResponse>> listPending(Pageable pageable) {
        return Mono.fromCallable(() -> paymentSubmissionRepository
                        .findAllByStatus(PaymentSubmissionStatus.PENDING_VERIFICATION, pageable)
                        .map(this::toResponse))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /** Admin confirms the payment actually landed. */
    public Mono<PaymentSubmissionResponse> verifyPayment(UUID submissionId, String adminId) {
        record Verified(
                PaymentSubmission submission, TourEnquiry enquiry, String tourName,
                boolean appliedToBooking, String bookingReference, BigDecimal remainingBalance
        ) {}

        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    PaymentSubmission submission = paymentSubmissionRepository.findByIdWithQuote(submissionId)
                            .orElseThrow(() -> new ResourceNotFoundException(
                                    HttpStatus.NOT_FOUND, "Payment submission not found: " + submissionId));

                    if (submission.getStatus() != PaymentSubmissionStatus.PENDING_VERIFICATION) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Only a pending submission can be verified. Current status: " + submission.getStatus());
                    }

                    submission.setStatus(PaymentSubmissionStatus.VERIFIED);
                    submission.setVerifiedBy(adminId);
                    submission.setVerifiedAt(Instant.now());
                    paymentSubmissionRepository.save(submission);

                    TourEnquiry enquiry = submission.getQuote().getEnquiry();
                    String tourName = enquiry.getTour().getName();

                    boolean appliedToBooking = false;
                    String bookingReference = null;
                    BigDecimal remainingBalance = null;

                    if (submission.getRelatedBookingId() != null) {
                        Booking booking = bookingRepository.findByIdAndDeletedFalse(submission.getRelatedBookingId())
                                .orElseThrow(() -> new CustomException(HttpStatus.INTERNAL_SERVER_ERROR,
                                        "Related booking not found: " + submission.getRelatedBookingId()));

                        try {
                            booking.recordPayment(submission.getAmountPaid(), submission.getReferenceCode());
                        } catch (IllegalArgumentException | IllegalStateException e) {
                            throw new CustomException(HttpStatus.CONFLICT, e.getMessage());
                        }
                        bookingRepository.save(booking);

                        appliedToBooking = true;
                        bookingReference = booking.getBookingReference();
                        remainingBalance = booking.getBalanceAmount();

                        activityService.log(
                                enquiry, ActorType.ADMIN, adminId,
                                ActivityAction.PAYMENT_VERIFIED, null, null,
                                "Balance payment of " + submission.getAmountPaid() + " verified and applied to booking "
                                        + bookingReference + " — remaining balance " + remainingBalance
                        );
                    } else {
                        activityService.log(
                                enquiry, ActorType.ADMIN, adminId,
                                ActivityAction.PAYMENT_VERIFIED, null, null,
                                "Payment verified for quote " + submission.getQuote().getId()
                        );
                    }

                    return new Verified(submission, enquiry, tourName, appliedToBooking, bookingReference, remainingBalance);
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(v -> {
                    Mono<Void> notify = v.appliedToBooking()
                            ? notificationService.sendBalancePaymentConfirmed(
                            v.enquiry(), v.tourName(), v.submission(), v.bookingReference(), v.remainingBalance())
                            : notificationService.sendPaymentVerifiedCustomerNotice(v.enquiry(), v.tourName(), v.submission());
                    return notify.thenReturn(v.submission());
                })
                .map(this::toResponse);
    }

    /** Admin rejects a claim — wrong amount, unmatched reference, etc. */
    public Mono<PaymentSubmissionResponse> rejectPayment(UUID submissionId, String adminId, RejectPaymentRequest req) {
        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    PaymentSubmission submission = paymentSubmissionRepository.findByIdWithQuote(submissionId)
                            .orElseThrow(() -> new ResourceNotFoundException(
                                    HttpStatus.NOT_FOUND, "Payment submission not found: " + submissionId));

                    if (submission.getStatus() != PaymentSubmissionStatus.PENDING_VERIFICATION) {
                        throw new IllegalStateException(
                                "Only a pending submission can be rejected. Current status: " + submission.getStatus());
                    }

                    submission.setStatus(PaymentSubmissionStatus.REJECTED);
                    submission.setVerifiedBy(adminId);
                    submission.setVerifiedAt(Instant.now());
                    submission.setRejectionReason(req.reason());
                    paymentSubmissionRepository.save(submission);

                    TourEnquiry enquiry = submission.getQuote().getEnquiry();

                    activityService.log(
                            enquiry, ActorType.ADMIN, adminId,
                            ActivityAction.PAYMENT_REJECTED, null, null,
                            "Payment claim rejected: " + req.reason()
                    );

                    return submission;
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .map(this::toResponse);
    }

    public Mono<Page<PaymentSubmissionResponse>> listByView(String view, Pageable pageable) {
        return Mono.fromCallable(() -> {
                    Page<PaymentSubmission> page = switch (view) {
                        case "pending" -> paymentSubmissionRepository
                                .findAllByStatus(PaymentSubmissionStatus.PENDING_VERIFICATION, pageable);
                        case "awaiting-booking" -> paymentSubmissionRepository.findVerifiedAwaitingBooking(pageable);
                        default -> throw new CustomException(HttpStatus.BAD_REQUEST, "Unknown view: " + view);
                    };
                    return page.map(this::toResponse);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /** Customer sees the payment claims for their own enquiry only. */
    public Mono<List<PaymentSubmissionResponse>> listForEnquiry(UUID enquiryId, String customerId) {
        return Mono.fromCallable(() -> {
                    ownershipGuard.mustFindOwnedBy(enquiryId, customerId); // throws if not theirs
                    return paymentSubmissionRepository.findAllByEnquiryId(enquiryId).stream()
                            .map(this::toResponse).toList();
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private PaymentSubmissionResponse toResponse(PaymentSubmission s) {
        EnquiryQuote quote = s.getQuote();
        TourEnquiry enquiry = quote.getEnquiry();
        Tour tour = enquiry.getTour();
        return new PaymentSubmissionResponse(
                s.getId(), quote.getId(), enquiry.getId(), tour.getId(),
                enquiry.getFullName(), tour.getName(),
                s.getChannel(), s.getReferenceCode(), s.getAmountPaid(),
                quote.getTotalPrice(), quote.getCurrency().name(),
                quote.getAdultCount(), quote.getChildCount(), s.getPayerName(),
                s.getStatus(), s.getVerifiedBy(), s.getVerifiedAt(), s.getRejectionReason(),
                enquiry.getBookingReference(), s.getCreatedDate(),
                s.getRelatedBookingReference() != null
        );
    }

}