package com.techStack.authSys.tour.notification;

import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.tour.models.EnquiryQuote;
import com.techStack.authSys.tour.models.PaymentSubmission;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourEnquiry;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.time.LocalTime;

public interface EnquiryNotificationService {

    Mono<Void> sendLeadNotification(TourEnquiry enquiry, String tourName);
    Mono<Void> sendAutoReply(TourEnquiry enquiry, String tourName);

    /** tourName passed explicitly -- enquiry.getTour() is LAZY and the
     *  caller's transaction/session is closed by the time notification
     *  fires, so this must be snapshotted before the call site returns. */
    Mono<Void> sendBookingConfirmed(TourEnquiry enquiry, String tourName);
    Mono<Void> sendFollowUpClosed(TourEnquiry enquiry, String tourName);

    /** quote.getEnquiry() is safe to read directly (assigned as a plain
     *  object reference in EnquiryQuoteService.createQuote, not a lazy
     *  proxy) -- but tourName still needs the same explicit snapshot. */
    Mono<Void> sendQuoteReady(EnquiryQuote quote, String tourName);

    // EnquiryNotificationService.java — add one method to the interface
    Mono<Void> sendQuoteReadyWhatsApp(EnquiryQuote quote, String tourName, String phone);

    Mono<Void> sendAppreciationNote(TourEnquiry enquiry, String tourName);

    // EnquiryNotificationService.java — add to interface
    Mono<Void> sendBookingConfirmedWithItinerary(
            TourEnquiry enquiry, Booking booking, Tour tour, String pickupLocation, LocalTime pickupTime);

    Mono<Void> sendQuoteAcceptedPaymentInstructions(EnquiryQuote quote, String tourName);

    Mono<Void> sendPaymentSubmittedAdminAlert(PaymentSubmission submission, TourEnquiry enquiry, String tourName, boolean isBalancePayment);
    Mono<Void> sendPaymentVerifiedCustomerNotice(TourEnquiry enquiry, String tourName, PaymentSubmission submission);
    Mono<Void> sendBalancePaymentConfirmed(TourEnquiry enquiry, String tourName, PaymentSubmission submission, String bookingReference, BigDecimal remainingBalance);

}