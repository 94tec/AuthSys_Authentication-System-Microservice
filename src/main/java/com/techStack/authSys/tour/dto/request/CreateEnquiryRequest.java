package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.PreferredContact;

import java.time.LocalDate;

public record CreateEnquiryRequest(
        String fullName,
        String email,
        String phone,
        PreferredContact preferredContact,
        LocalDate preferredDate,
        Boolean flexibleDates,
        Integer groupSizeAdults,
        Integer groupSizeChildren,
        String budgetRange,
        String requirements,
        String source,
        Boolean consent
) {}