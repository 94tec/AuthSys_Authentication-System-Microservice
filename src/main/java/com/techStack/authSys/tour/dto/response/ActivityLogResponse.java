package com.techStack.authSys.tour.dto.response;

import com.techStack.authSys.tour.models.ActivityAction;
import com.techStack.authSys.tour.models.ActorType;
import com.techStack.authSys.tour.models.TourEnquiryStatus;
import java.time.Instant;
import java.util.UUID;

public record ActivityLogResponse(
        UUID id, ActorType actorType, String actorId,
        ActivityAction action, TourEnquiryStatus fromStatus, TourEnquiryStatus toStatus,
        String note, Instant createdDate
) {}
