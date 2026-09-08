package com.techStack.authSys.tour.services;

import com.techStack.authSys.tour.models.*;
import com.techStack.authSys.tour.repository.EnquiryEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
class EnquiryActivityService {

    private final EnquiryEventRepository eventRepository;

    void log(TourEnquiry enquiry, ActorType actorType, String actorId, ActivityAction eventType,
             TourEnquiryStatus from, TourEnquiryStatus to, String details) {
        eventRepository.save(EnquiryEvent.builder()
                .enquiry(enquiry)
                .actorType(actorType)
                .actorId(actorId)
                .eventType(eventType)
                .fromStatus(from)
                .toStatus(to)
                .details(details)
                .build());
    }
}