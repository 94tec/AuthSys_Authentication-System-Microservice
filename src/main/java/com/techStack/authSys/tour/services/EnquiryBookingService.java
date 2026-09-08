package com.techStack.authSys.tour.services;

import com.techStack.authSys.availability.models.TourAvailability;
import com.techStack.authSys.availability.repository.TourAvailabilityRepository;
import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.models.BookingStatus;
import com.techStack.authSys.booking.models.BookingTraveler;
import com.techStack.authSys.booking.models.PaymentStatus;
import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.booking.service.BookingService;
import com.techStack.authSys.common.exception.CustomException;
import com.techStack.authSys.tour.dto.request.CreateBookingFromPaymentRequest;
import com.techStack.authSys.tour.dto.response.BookingCreatedResponse;
import com.techStack.authSys.tour.models.*;
import com.techStack.authSys.tour.notification.EnquiryNotificationService;
import com.techStack.authSys.tour.repository.PaymentSubmissionRepository;
import com.techStack.authSys.tour.repository.TourEnquiryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EnquiryBookingService {

    private final PaymentSubmissionRepository paymentSubmissionRepository;
    private final TourEnquiryRepository enquiryRepository;
    private final TourAvailabilityRepository availabilityRepository;
    private final BookingRepository bookingRepository;
    private final BookingService bookingService; // for generateBookingReference()
    private final EnquiryActivityService activityService;
    private final EnquiryNotificationService notificationService;
    private final TransactionTemplate transactionTemplate;

    public Mono<BookingCreatedResponse> createBookingFromVerifiedPayment(
            UUID paymentSubmissionId, String adminId, CreateBookingFromPaymentRequest req
    ) {
        record Created(Booking booking, TourEnquiry enquiry, Tour tour, TourAvailability slot) {}

        return Mono.fromCallable(() -> transactionTemplate.execute(status -> {
                    PaymentSubmission submission = paymentSubmissionRepository.findByIdWithQuote(paymentSubmissionId)
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Payment submission not found: " + paymentSubmissionId));

                    if (submission.getStatus() != PaymentSubmissionStatus.VERIFIED) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Cannot create a booking until payment is VERIFIED. Current status: " + submission.getStatus());
                    }

                    EnquiryQuote quote = submission.getQuote();
                    TourEnquiry enquiry = quote.getEnquiry();
                    Tour tour = enquiry.getTour(); // read while session is open

                    if (enquiry.getBookingReference() != null) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "This enquiry already has a booking: " + enquiry.getBookingReference());
                    }

                    int requestedCount = quote.getAdultCount() + quote.getChildCount();
                    if (req.travelers().size() != requestedCount) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Traveler list size (" + req.travelers().size()
                                        + ") must match the quoted party size (" + requestedCount + ")");
                    }

                    TourAvailability slot = availabilityRepository.findById(req.availabilityId())
                            .orElseThrow(() -> new CustomException(
                                    HttpStatus.NOT_FOUND, "Availability slot not found: " + req.availabilityId()));

                    if (!slot.getTour().getId().equals(tour.getId())) {
                        throw new CustomException(HttpStatus.BAD_REQUEST,
                                "Availability slot does not belong to the quoted tour");
                    }

                    long existing = bookingRepository.countActiveBookingForCustomerOnSlot(
                            slot.getId(), enquiry.getUserId());
                    if (existing > 0) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "This customer already has an active booking for this tour date");
                    }

                    if (!slot.hasAvailability(requestedCount)) {
                        throw new CustomException(HttpStatus.CONFLICT,
                                "Not enough slots available. Requested: " + requestedCount
                                        + ", available: " + slot.getAvailableSlots());
                    }

                    String bookingReference = bookingService.generateBookingReference();

                    BigDecimal pricePerTraveler = quote.getAdultCount() > 0
                            ? quote.getPricePerAdult()
                            : quote.getPricePerChild();

                    Booking booking = Booking.builder()
                            .bookingReference(bookingReference)
                            .customerId(enquiry.getUserId())
                            .customerEmail(enquiry.getEmail())
                            .customerName(enquiry.getFullName())
                            .tour(tour)
                            .availability(slot)
                            .tourDate(slot.getDate())
                            .tourName(tour.getName())
                            .travelerCount(requestedCount)
                            .numberOfAdults(quote.getAdultCount())
                            .numberOfChildren(quote.getChildCount())
                            .pricePerTraveler(pricePerTraveler)
                            .subtotal(quote.getTotalPrice())
                            .discount(BigDecimal.ZERO)
                            .totalPrice(quote.getTotalPrice())
                            .currency(quote.getCurrency().name())
                            .depositAmount(BigDecimal.ZERO) // already fully verified-paid
                            .amountPaid(submission.getAmountPaid())
                            .balanceAmount(quote.getTotalPrice().subtract(submission.getAmountPaid()).max(BigDecimal.ZERO))
                            .paymentStatus(submission.getAmountPaid().compareTo(quote.getTotalPrice()) >= 0
                                    ? PaymentStatus.PAID : PaymentStatus.PARTIALLY_PAID)
                            .status(BookingStatus.CONFIRMED)
                            .paymentReference(submission.getReferenceCode())
                            .paidAt(submission.getVerifiedAt())
                            .specialRequests(req.specialInstructions())
                            .build();

                    for (int i = 0; i < req.travelers().size(); i++) {
                        CreateBookingFromPaymentRequest.TravelerInfo t = req.travelers().get(i);
                        booking.addTraveler(BookingTraveler.builder()
                                .fullName(t.fullName())
                                .dateOfBirth(t.dateOfBirth())
                                .passportNumber(t.passportNumber())
                                .nationality(t.nationality())
                                .dietaryNotes(t.dietaryNotes())
                                .leadTraveler(i == 0)
                                .build());
                    }

                    // Same order as BookingService.createBooking: reserve on the slot,
                    // save the slot first (triggers the @Version optimistic-lock check),
                    // then save the booking.
                    slot.reserveSlots(requestedCount);
                    availabilityRepository.save(slot);

                    Booking saved = bookingRepository.save(booking);

                    enquiry.setBookingReference(bookingReference);
                    enquiry.setTravelStartDate(slot.getDate());
                    enquiry.setTravelEndDate(slot.getReturnDate());
                    enquiry.setStatus(TourEnquiryStatus.CONVERTED);
                    enquiryRepository.save(enquiry);

                    activityService.log(
                            enquiry, ActorType.ADMIN, adminId,
                            ActivityAction.BOOKING_CREATED, null, null,
                            "Booking " + bookingReference + " created from verified payment " + submission.getId()
                    );

                    return new Created(saved, enquiry, tour, slot);
                }))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(OptimisticLockingFailureException.class, e -> {
                    log.warn("Concurrent booking conflict for availability {}: {}", req.availabilityId(), e.getMessage());
                    return Mono.error(new CustomException(HttpStatus.CONFLICT,
                            "This slot was just taken. Please select another date."));
                })
                .onErrorResume(IllegalStateException.class, e ->
                        Mono.error(new CustomException(HttpStatus.CONFLICT, e.getMessage())))
                .flatMap(created ->
                        notificationService.sendBookingConfirmedWithItinerary(
                                        created.enquiry(), created.booking(), created.tour(),
                                        req.pickupLocation(), req.pickupTime())
                                .thenReturn(created)
                )
                .map(created -> new BookingCreatedResponse(
                        created.booking().getId(), created.booking().getBookingReference(),
                        created.tour().getName(), created.slot().getDate(), created.slot().getReturnDate(),
                        req.pickupLocation(), req.pickupTime(),
                        created.booking().getTotalPrice(), created.booking().getCurrency()
                ));
    }
}