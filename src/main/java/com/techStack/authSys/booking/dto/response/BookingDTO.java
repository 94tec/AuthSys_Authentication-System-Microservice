package com.techStack.authSys.booking.dto.response;

import com.techStack.authSys.booking.models.BookingStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public record BookingDTO(

        // Identity
        UUID id,

        // Customer
        String customerId,
        String customerName,
        String customerEmail,

        // Tour
        UUID tourId,
        UUID availabilityId,
        String tourName,
        LocalDate tourDate,

        // Booking
        BookingStatus status,
        String statusDescription,
        int travelerCount,
        List<TravelerDTO> travelers,

        // Pricing
        BigDecimal pricePerTraveler,
        BigDecimal totalPrice,
        String currency,

        // Payment
        UUID paymentId,
        String paymentReference,
        Instant paidAt,

        // Cancellation / Refund
        Instant cancelledAt,
        String cancellationReason,
        String refundReference,
        Instant refundedAt,

        // Customer Notes
        String specialRequests,

        // Audit
        Instant createdDate,
        Instant lastModifiedDate

) {

    public record TravelerDTO(
            UUID id,
            String fullName,
            String nationality,
            String dietaryNotes,
            boolean leadTraveler
    ) {}
}