package com.techStack.authSys.availability.dto.request;

import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.time.OffsetDateTime;

/**
 * Patch-style update for an existing availability slot.
 * PUT /api/availability/{id}
 *
 * Only non-null fields are applied (same pattern as UpdateTourRequest).
 * maxSlots and date are not updatable after creation — delete and recreate.
 */
public record UpdateAvailabilityRequest(

        /** Adjust remaining capacity — cannot exceed the slot's maxSlots */
        @Min(value = 0, message = "Available slots cannot be negative")
        Integer availableSlots,

        /** Move or clear the booking deadline */
        OffsetDateTime bookingDeadline,

        /** Override or clear per-date pricing */
        @DecimalMin(value = "0.00", message = "Price override must be positive")
        BigDecimal priceOverride,

        @Size(max = 500)
        String internalNotes

) {}
