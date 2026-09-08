package com.techStack.authSys.tour.services;

import com.techStack.authSys.common.exception.ResourceNotFoundException;
import com.techStack.authSys.tour.models.TourEnquiry;
import com.techStack.authSys.tour.repository.TourEnquiryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Centralizes the "does this enquiry exist AND belong to this customer" check.
 * Returns 404 (not 403) on a mismatched owner so enquiry IDs can't be enumerated
 * by a logged-in customer probing other people's leads.
 */
@Component
@RequiredArgsConstructor
class EnquiryOwnershipGuard {

    private final TourEnquiryRepository enquiryRepository;

    TourEnquiry mustFind(UUID id) {
        return enquiryRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException(
                        HttpStatus.NOT_FOUND, "Enquiry not found: " + id));
    }

    TourEnquiry mustFindOwnedBy(UUID id, String userId) {
        TourEnquiry e = mustFind(id);
        if (!e.getUserId().equals(userId)) {
            throw new ResourceNotFoundException(HttpStatus.NOT_FOUND, "Enquiry not found: " + id);
        }
        return e;
    }
}