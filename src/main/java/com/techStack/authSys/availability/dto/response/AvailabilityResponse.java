package com.techStack.authSys.availability.dto.response;

import com.techStack.authSys.availability.models.AvailabilityStatus;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Full availability slot response — returned for staff/admin views.
 * Includes internal notes, occupancy stats, and booked count.
 */
@Data
@Builder
public class AvailabilityResponse {

    private UUID   id;
    private UUID   tourId;
    private String tourName;
    private String tourSlug;

    private LocalDate date;

    // Capacity
    private Integer maxSlots;
    private Integer availableSlots;
    private Integer bookedCount;          // maxSlots - availableSlots
    private Double  occupancyPercent;     // booked / max * 100

    // Status
    private AvailabilityStatus status;
    private String             statusDescription;

    // Pricing
    private BigDecimal tourBasePrice;     // enquire-button.tsx.pricePerPerson
    private BigDecimal priceOverride;     // null if no override
    private BigDecimal effectivePrice;    // override ?? base

    // Optional fields
    private OffsetDateTime bookingDeadline;
    private String         internalNotes;   // staff only

    // Audit
    private OffsetDateTime createdDate;
    private OffsetDateTime lastModifiedDate;
}
