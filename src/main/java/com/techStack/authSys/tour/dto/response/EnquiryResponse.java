package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.*;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record EnquiryResponse(
        UUID id,
        UUID tourId,
        String tourName,
        String fullName,
        String email,
        String phone,
        PreferredContact preferredContact,
        LocalDate preferredDate,
        Integer groupSizeAdults,
        Integer groupSizeChildren,
        String budgetRange,
        String requirements,
        TourEnquiryStatus status,
        Instant createdDate,
        Instant lastModifiedDate
) {}