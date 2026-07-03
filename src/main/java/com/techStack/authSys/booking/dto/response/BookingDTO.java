package com.techStack.authSys.booking.dto.response;

import com.techStack.authSys.booking.models.BookingStatus;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public record BookingDTO(

        UUID id,

        // Customer
        String customerId,
        String customerEmail,
        String customerName,

        // Tour
        UUID tourId,
        String tourName,
        LocalDate tourDate,

        // Party
        int travelerCount,
        List<TravelerDTO> travelers,

        // Pricing — snapshot at booking time
        BigDecimal pricePerTraveler,
        BigDecimal totalPrice,
        String currency,

        // Lifecycle
        BookingStatus status,
        String statusDescription,

        // Payment
        String paymentReference,
        Instant paidAt,

        // Cancellation / refund
        Instant cancelledAt,
        String cancellationReason,
        String refundReference,
        Instant refundedAt,

        // Notes
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