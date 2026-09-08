package com.techStack.authSys.availability.dto.response;

import com.techStack.authSys.availability.models.AvailabilityStatus;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Lightweight response for the public booking calendar and customer-facing views.
 * Excludes internal notes, audit timestamps, and occupancy details.
 */
@Data
@Builder
public class AvailabilitySummaryResponse {

    private UUID               id;
    private LocalDate          date;
    private Integer            availableSlots;
    private AvailabilityStatus status;
    private BigDecimal         effectivePrice;   // override ?? enquire-button.tsx base price
    private OffsetDateTime     bookingDeadline;
}
