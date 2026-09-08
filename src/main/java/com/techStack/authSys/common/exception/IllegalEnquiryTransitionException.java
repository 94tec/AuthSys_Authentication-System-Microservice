package com.techStack.authSys.common.exception;

import com.techStack.authSys.tour.models.TourEnquiryStatus;

public class IllegalEnquiryTransitionException extends RuntimeException {
    public IllegalEnquiryTransitionException(TourEnquiryStatus from, TourEnquiryStatus to) {
        super("Cannot move enquiry from %s to %s".formatted(from, to));
    }
}