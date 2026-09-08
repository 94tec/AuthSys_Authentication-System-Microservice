package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.PreferredContact;
import com.techStack.authSys.tour.models.TourEnquiryStatus;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public record EnquiryDetailResponse(
        UUID id, UUID tourId, String tourName,
        String fullName, String email, String phone,
        PreferredContact preferredContact, LocalDate preferredDate, Boolean flexibleDates,
        Integer groupSizeAdults, Integer groupSizeChildren,
        String budgetRange, String requirements,
        TourEnquiryStatus status, String assignedTo,
        LocalDate travelStartDate, LocalDate travelEndDate,
        String bookingReference, Instant appreciationSentAt,
        List<QuoteResponse> quotes, List<ActivityLogResponse> activity,
        Instant createdDate, Instant lastModifiedDate,
        BigDecimal bookingTotalPrice, BigDecimal bookingAmountPaid,
        BigDecimal bookingBalanceAmount, String bookingPaymentStatus
) {}