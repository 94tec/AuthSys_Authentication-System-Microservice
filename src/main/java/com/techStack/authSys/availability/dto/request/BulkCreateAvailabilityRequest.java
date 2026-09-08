package com.techStack.authSys.availability.dto.request;

import jakarta.validation.constraints.*;

import java.math.BigDecimal;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.Set;
import java.util.UUID;

/**
 * Bulk-create availability slots across a date range.
 * POST /api/availability/bulk
 *
 * Example: create Saturday slots for every week in December.
 *   tourId        = <uuid>
 *   from          = 2025-12-01
 *   to            = 2025-12-31
 *   daysOfWeek    = [SATURDAY]
 *   maxSlots      = 12
 *
 * Dates that already have a slot are skipped (no duplicate error).
 * Dates in the past relative to today are skipped automatically.
 */
public record BulkCreateAvailabilityRequest(

        @NotNull(message = "Tour ID is required")
        UUID tourId,

        @NotNull(message = "Start date is required")
        LocalDate from,

        @NotNull(message = "End date is required")
        LocalDate to,

        /**
         * Days of the week to create slots on.
         * Null or empty = create a slot on every day in the range.
         */
        Set<DayOfWeek> daysOfWeek,

        @NotNull(message = "Max slots is required")
        @Min(value = 1, message = "At least 1 slot required")
        @Max(value = 500, message = "Cannot exceed 500 slots")
        Integer maxSlots,

        OffsetDateTime bookingDeadlineOffset,

        @DecimalMin(value = "0.00", message = "Price override must be positive")
        BigDecimal priceOverride,

        @Size(max = 500)
        String internalNotes

) {}
