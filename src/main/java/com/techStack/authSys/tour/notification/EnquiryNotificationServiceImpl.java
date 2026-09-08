package com.techStack.authSys.tour.notification;


import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.notification.service.EmailServiceInstance;
import com.techStack.authSys.tour.models.PaymentSubmission;
import com.techStack.authSys.tour.models.EnquiryQuote;
import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourEnquiry;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.LocalTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Injects the CONCRETE EmailServiceInstance rather than the EmailService
 * interface, because sendTemplatedEmail() is only defined on the concrete
 * class in this codebase, not declared on the interface. If you later
 * promote sendTemplatedEmail() onto the EmailService interface, switch
 * this back to the interface type -- nothing else here needs to change.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EnquiryNotificationServiceImpl implements EnquiryNotificationService {

    private final EmailServiceInstance emailService;
    private final WhatsAppService whatsAppService;
    private final Clock clock;

    @Value("${enquiry.notification.internal-recipient}")
    private String internalRecipient;

    @Value("${app.frontend-base-url}")
    private String frontendBaseUrl;

    @Override
    public Mono<Void> sendLeadNotification(TourEnquiry enquiry, String tourName) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("enquiryName",     enquiry.getFullName());
        vars.put("enquiryEmail",    enquiry.getEmail());
        vars.put("enquiryPhone",    enquiry.getPhone() != null ? enquiry.getPhone() : "-");
        vars.put("preferredContact", enquiry.getPreferredContact() != null ? enquiry.getPreferredContact() : "-");
        vars.put("tourName",        tourName);
        vars.put("preferredDate",   enquiry.getPreferredDate() != null ? enquiry.getPreferredDate().toString() : "Not specified");
        vars.put("preferredDates",  enquiry.getPreferredDate());
        vars.put("groupSizeAdults",   enquiry.getGroupSizeAdults()   != null ? enquiry.getGroupSizeAdults()   : 0);
        vars.put("groupSizeChildren", enquiry.getGroupSizeChildren() != null ? enquiry.getGroupSizeChildren() : 0);
        vars.put("budgetRange",     enquiry.getBudgetRange() != null ? enquiry.getBudgetRange() : "Not specified");
        vars.put("requirements",    enquiry.getRequirements() != null ? enquiry.getRequirements() : "None provided"); // was getRequirements()
        vars.put("adminUrl",        frontendBaseUrl + "/admin/enquiries?highlight=" + enquiry.getId());
        vars.put("receivedAt",      clock.instant());

        return emailService.sendTemplatedEmail(
                        internalRecipient,
                        String.format("New enquiry: %s - %s", tourName, enquiry.getFullName()), // was getName()
                        "emails/enquiries/lead-notification",
                        vars
                )
                .doOnSuccess(v -> log.info("Lead notification sent for enquiry {}", enquiry.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send lead notification for enquiry {}: {}", enquiry.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendAutoReply(TourEnquiry enquiry, String tourName) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());  // was getName()
        vars.put("tourName", tourName);
        vars.put("preferredContact", enquiry.getPreferredContact() != null
                ? enquiry.getPreferredContact().toString().toLowerCase()
                : "email");

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        "We've received your request - Damuchi Safaris",
                        "emails/enquiries/auto-reply",
                        vars
                )
                .doOnSuccess(v -> log.info("Auto-reply sent for enquiry {}", enquiry.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send auto-reply for enquiry {}: {}", enquiry.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendBookingConfirmed(TourEnquiry enquiry, String tourName) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("bookingReference", enquiry.getBookingReference() != null ? enquiry.getBookingReference() : "-");
        vars.put("travelStartDate", enquiry.getTravelStartDate() != null ? enquiry.getTravelStartDate().toString() : "-");
        vars.put("travelEndDate", enquiry.getTravelEndDate() != null ? enquiry.getTravelEndDate().toString() : "-");

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        String.format("Booking confirmed: %s", tourName),
                        "emails/enquiries/booking-confirmed",
                        vars
                )
                .doOnSuccess(v -> log.info("Booking confirmation sent for enquiry {}", enquiry.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send booking confirmation for enquiry {}: {}", enquiry.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendFollowUpClosed(TourEnquiry enquiry, String tourName) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        String.format("Regarding your %s enquiry", tourName),
                        "emails/enquiries/followup-closed",
                        vars
                )
                .doOnSuccess(v -> log.info("Follow-up-closed notice sent for enquiry {}", enquiry.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send follow-up-closed notice for enquiry {}: {}", enquiry.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendQuoteReady(EnquiryQuote quote, String tourName) {
        TourEnquiry enquiry = quote.getEnquiry();

        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("pricePerAdult", quote.getPricePerAdult());
        vars.put("pricePerChild", quote.getPricePerChild() != null ? quote.getPricePerChild() : "-");
        vars.put("totalPrice", quote.getTotalPrice());
        vars.put("currency", quote.getCurrency());
        vars.put("validUntil", quote.getValidUntil().toString());
        vars.put("inclusionsNote", quote.getInclusionsNote() != null ? quote.getInclusionsNote() : "");
        vars.put("acceptUrl", frontendBaseUrl + "/me/enquiries/" + enquiry.getId()
                + "/quotes/" + quote.getId());

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        String.format("Your quote for %s is ready", tourName),
                        "emails/enquiries/quote-ready",
                        vars
                )
                .doOnSuccess(v -> log.info("Quote-ready notice sent for quote {}", quote.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send quote-ready notice for quote {}: {}", quote.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendQuoteReadyWhatsApp(EnquiryQuote quote, String tourName, String phone) {
        TourEnquiry enquiry = quote.getEnquiry();

        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("totalPrice", quote.getTotalPrice());
        vars.put("currency", quote.getCurrency());
        vars.put("validUntil", quote.getValidUntil().toString());
        vars.put("acceptUrl", frontendBaseUrl + "/me/enquiries/" + enquiry.getId()
                + "/quotes/" + quote.getId());

        return whatsAppService.sendTemplatedMessage(
                        phone,
                        "quote_ready", // WhatsApp Business template name, must be pre-approved by Meta
                        vars
                )
                .doOnSuccess(v -> log.info("WhatsApp quote-ready sent for quote {}", quote.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send WhatsApp quote-ready for quote {}: {}", quote.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendAppreciationNote(TourEnquiry enquiry, String tourName) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("travelStartDate", enquiry.getTravelStartDate() != null ? enquiry.getTravelStartDate().toString() : "-");
        vars.put("travelEndDate", enquiry.getTravelEndDate() != null ? enquiry.getTravelEndDate().toString() : "-");

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        String.format("Thank you for traveling with Damuchi Safaris - %s", tourName),
                        "emails/enquiries/appreciation-note",
                        vars
                )
                .doOnSuccess(v -> log.info("Appreciation note sent for enquiry {}", enquiry.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send appreciation note for enquiry {}: {}", enquiry.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    // EnquiryNotificationServiceImpl.java
    @Override
    public Mono<Void> sendBookingConfirmedWithItinerary(
            TourEnquiry enquiry, Booking booking, Tour tour, String pickupLocation, LocalTime pickupTime) {

        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tour.getName());
        vars.put("bookingReference", booking.getBookingReference());
        vars.put("travelStartDate", enquiry.getTravelStartDate() != null ? enquiry.getTravelStartDate().toString() : "-");
        vars.put("travelEndDate", enquiry.getTravelEndDate() != null ? enquiry.getTravelEndDate().toString() : "-");
        vars.put("pickupLocation", pickupLocation != null ? pickupLocation : "To be confirmed by our team");
        vars.put("pickupTime", pickupTime != null ? pickupTime.toString() : "To be confirmed");
        vars.put("itinerary", tour.getItinerary()); // reuses Tour's existing List<String> — no new field needed
        vars.put("inclusions", tour.getInclusions());
        vars.put("exclusions", tour.getExclusions());
        vars.put("importantInformation", tour.getImportantInformation());
        vars.put("totalPrice", booking.getTotalPrice());
        vars.put("currency", booking.getCurrency());

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        String.format("Booking confirmed: %s (%s)", tour.getName(), booking.getBookingReference()),
                        "emails/enquiries/booking-confirmed-full",
                        vars
                )
                .doOnSuccess(v -> log.info("Full booking confirmation sent for booking {}", booking.getBookingReference()))
                .onErrorResume(e -> {
                    log.warn("Failed to send booking confirmation for {}: {}", booking.getBookingReference(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendQuoteAcceptedPaymentInstructions(EnquiryQuote quote, String tourName) {
        TourEnquiry enquiry = quote.getEnquiry();
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("totalPrice", quote.getTotalPrice());
        vars.put("currency", quote.getCurrency());
        vars.put("paymentUrl", frontendBaseUrl + "/me/enquiries/" + enquiry.getId());

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        String.format("Next step: pay your deposit for %s", tourName),
                        "emails/enquiries/quote-accepted",
                        vars)
                .doOnSuccess(v -> log.info("Quote-accepted notice sent for quote {}", quote.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send quote-accepted notice for quote {}: {}", quote.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendPaymentSubmittedAdminAlert(
            PaymentSubmission submission, TourEnquiry enquiry, String tourName, boolean isBalancePayment) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("customerName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("channel", submission.getChannel());
        vars.put("referenceCode", submission.getReferenceCode());
        vars.put("amountPaid", submission.getAmountPaid());
        vars.put("isBalancePayment", isBalancePayment);
        vars.put("adminUrl", frontendBaseUrl + "/admin/payments?highlight=" + submission.getId());

        String subject = (isBalancePayment ? "Balance payment claim: " : "Payment claim submitted: ")
                + tourName + " - " + enquiry.getFullName();

        return emailService.sendTemplatedEmail(internalRecipient, subject, "emails/enquiries/payment-submitted", vars)
                .doOnSuccess(v -> log.info("Payment-submitted admin alert sent for submission {}", submission.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send payment-submitted alert for submission {}: {}", submission.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendPaymentVerifiedCustomerNotice(TourEnquiry enquiry, String tourName, PaymentSubmission submission) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("amountPaid", submission.getAmountPaid());

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        "Payment verified: " + tourName,
                        "emails/enquiries/payment-verified",
                        vars)
                .doOnSuccess(v -> log.info("Payment-verified notice sent for submission {}", submission.getId()))
                .onErrorResume(e -> {
                    log.warn("Failed to send payment-verified notice for submission {}: {}", submission.getId(), e.getMessage());
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> sendBalancePaymentConfirmed(
            TourEnquiry enquiry, String tourName, PaymentSubmission submission, String bookingReference, BigDecimal remainingBalance) {
        Map<String, Object> vars = new HashMap<>();
        vars.put("fullName", enquiry.getFullName());
        vars.put("tourName", tourName);
        vars.put("bookingReference", bookingReference);
        vars.put("amountPaid", submission.getAmountPaid());
        vars.put("remainingBalance", remainingBalance);
        vars.put("fullyPaid", remainingBalance.signum() <= 0);

        return emailService.sendTemplatedEmail(
                        enquiry.getEmail(),
                        (remainingBalance.signum() <= 0 ? "Fully paid: " : "Balance payment received: ") + tourName,
                        "emails/enquiries/balance-payment-confirmed",
                        vars)
                .doOnSuccess(v -> log.info("Balance-payment-confirmed notice sent for booking {}", bookingReference))
                .onErrorResume(e -> {
                    log.warn("Failed to send balance-payment-confirmed notice for booking {}: {}", bookingReference, e.getMessage());
                    return Mono.empty();
                });
    }
}