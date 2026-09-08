package com.techStack.authSys.booking.mapper;

import com.techStack.authSys.booking.dto.response.BookingDTO;
import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.models.BookingTraveler;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

/**
 * BookingMapper
 *
 * Maps Booking entity → BookingDTO.
 * Kept as a plain @Component (no MapStruct) to stay consistent
 * with the manual mapper pattern used elsewhere in authSys
 * (e.g. PublicUser static mapper, AuditLogDTO mapper).
 *
 * Travelers are included only when the collection is initialized —
 * guards against LazyInitializationException if called outside a
 * transaction with an uninitialized travelers collection.
 */
@Component
public class BookingMapper {

    public BookingDTO toDTO(Booking booking) {

        return new BookingDTO(

                // Identity
                booking.getId(),

                // Customer
                booking.getCustomerId(),
                booking.getCustomerName(),
                booking.getCustomerEmail(),

                // Tour
                booking.getTour() != null ? booking.getTour().getId() : null,
                booking.getAvailability() != null ? booking.getAvailability().getId() : null,
                booking.getTourName(),
                booking.getTourDate(),

                // Booking
                booking.getStatus(),
                booking.getStatus() != null
                        ? booking.getStatus().getDescription()
                        : null,
                booking.getTravelerCount(),
                mapTravelers(booking),

                // Pricing
                booking.getPricePerTraveler(),
                booking.getTotalPrice(),
                booking.getCurrency(),

                // Payment
                null, // Replace with booking.getPayment().getId() if you have a Payment entity
                booking.getPaymentReference(),
                booking.getPaidAt(),

                // Cancellation / Refund
                booking.getCancelledAt(),
                booking.getCancellationReason(),
                booking.getRefundReference(),
                booking.getRefundedAt(),

                // Notes
                booking.getSpecialRequests(),

                // Audit
                booking.getCreatedDate(),
                booking.getLastModifiedDate()
        );
    }

    private List<BookingDTO.TravelerDTO> mapTravelers(Booking booking) {
        try {
            if (booking.getTravelers() == null) {
                return Collections.emptyList();
            }
            return booking.getTravelers()
                    .stream()
                    .filter(t -> !t.isDeleted())
                    .map(this::toTravelerDTO)
                    .toList();
        } catch (Exception e) {
            // Lazy collection not initialized — return empty rather than throw.
            // Callers that need travelers should ensure the entity is loaded
            // within a transaction with travelers fetched (e.g. JOIN FETCH).
            return Collections.emptyList();
        }
    }

    private BookingDTO.TravelerDTO toTravelerDTO(BookingTraveler t) {
        return new BookingDTO.TravelerDTO(
                t.getId(),
                t.getFullName(),
                t.getNationality(),
                t.getDietaryNotes(),
                t.isLeadTraveler()
        );
    }
}