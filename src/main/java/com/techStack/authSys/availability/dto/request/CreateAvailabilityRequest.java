package com.techStack.authSys.availability.dto.request;

import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Request to create a single availability slot.
 * POST /api/availability
 *
 * For bulk creation across a date range, use BulkCreateAvailabilityRequest.
 */
public record CreateAvailabilityRequest(

        @NotNull(message = "Tour ID is required")
        UUID tourId,

        @NotNull(message = "Date is required")
        @Future(message = "Slot date must be in the future")
        LocalDate date,

        @NotNull(message = "Max slots is required")
        @Min(value = 1, message = "At least 1 slot required")
        @Max(value = 500, message = "Cannot exceed 500 slots")
        Integer maxSlots,

        /**
         * Defaults to maxSlots in AvailabilityService.createSlot() if null.
         * Allows pre-filling the slot partially for pre-reserved groups.
         */
        @Min(value = 0, message = "Available slots cannot be negative")
        Integer availableSlots,

        /** Optional booking cutoff — null means no deadline */
        OffsetDateTime bookingDeadline,

        /** Optional per-date price override — null uses enquire-button.tsx.pricePerPerson */
        @DecimalMin(value = "0.00", message = "Price override must be positive")
        BigDecimal priceOverride,

        @Size(max = 500, message = "Notes must be under 500 characters")
        String internalNotes

) {}
