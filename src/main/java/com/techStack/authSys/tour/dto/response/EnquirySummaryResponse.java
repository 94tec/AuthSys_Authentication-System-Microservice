package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.TourEnquiryStatus;
import java.time.Instant;
import java.util.UUID;

/** Lightweight row for admin list views — no activity log, no quotes. */
public record EnquirySummaryResponse(
        UUID id, UUID tourId, String tourName,
        String fullName, String email,
        TourEnquiryStatus status, String assignedTo,
        Instant createdDate, Instant lastModifiedDate
) {}
