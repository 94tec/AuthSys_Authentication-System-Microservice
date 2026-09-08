package com.techStack.authSys.tour.dto.request;

import com.techStack.authSys.tour.models.TourEnquiryStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateEnquiryStatusRequest(
        @NotNull TourEnquiryStatus status,
        String note
) {}