package com.techStack.authSys.tour.services;

import com.techStack.authSys.common.exception.IllegalEnquiryTransitionException;
import com.techStack.authSys.tour.models.TourEnquiryStatus;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

import static com.techStack.authSys.tour.models.TourEnquiryStatus.*;

@Component
public class EnquiryStatusTransitions {

    private static final Map<TourEnquiryStatus, Set<TourEnquiryStatus>> ALLOWED = Map.of(
            NEW,       Set.of(CONTACTED, LOST),
            CONTACTED, Set.of(QUOTED, LOST),
            QUOTED,    Set.of(CONVERTED, LOST),
            CONVERTED, Set.of(COMPLETED),
            COMPLETED, Set.of(ARCHIVED),
            LOST,      Set.of(ARCHIVED),
            ARCHIVED,  Set.of()
    );

    public boolean isAllowed(TourEnquiryStatus from, TourEnquiryStatus to) {
        return ALLOWED.getOrDefault(from, Set.of()).contains(to);
    }

    public void assertAllowed(TourEnquiryStatus from, TourEnquiryStatus to) {
        if (from == to) return; // idempotent no-op, not an error
        if (!isAllowed(from, to)) {
            throw new IllegalEnquiryTransitionException(from, to);
        }
    }
}