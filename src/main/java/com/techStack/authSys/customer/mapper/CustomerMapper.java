package com.techStack.authSys.customer.mapper;

import com.techStack.authSys.customer.dto.response.CustomerProfileResponse;
import com.techStack.authSys.customer.dto.response.CustomerSummaryResponse;
import com.techStack.authSys.customer.dto.response.TravelDocumentResponse;
import com.techStack.authSys.customer.models.CustomerProfile;
import com.techStack.authSys.customer.models.TravelDocument;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.ZoneOffset;

/**
 * CustomerMapper — entity → DTO conversions.
 *
 * Called by CustomerService. No reverse mapping — entities are built
 * directly using builder pattern in the service.
 */
@Component
public class CustomerMapper {

    public CustomerProfileResponse toProfileResponse(CustomerProfile p) {
        return CustomerProfileResponse.builder()
            .id(p.getId())
            .customerId(p.getCustomerId())
            .firstName(p.getFirstName())
            .lastName(p.getLastName())
            .fullName(p.getFullName())
            .email(p.getEmail())
            .phoneNumber(p.getPhoneNumber())
            .bio(p.getBio())
            .country(p.getCountry())
            .photoUrl(p.getPhotoUrl())
            .dateOfBirth(p.getDateOfBirth())
            .nationality(p.getNationality())
            .dietaryNotes(p.getDietaryNotes())
            .emailMarketingOptIn(p.isEmailMarketingOptIn())
            .smsOptIn(p.isSmsOptIn())
            .savedTourIds(p.getSavedTourIds())
            .wishlistCount(p.getSavedTourIds() != null ? p.getSavedTourIds().size() : 0)
            .documentCount(p.getTravelDocuments() != null ? p.getTravelDocuments().size() : 0)
            .hasPrimaryDocument(p.getTravelDocuments() != null
                && p.getTravelDocuments().stream().anyMatch(TravelDocument::isPrimaryDocument))
            .totalToursCompleted(p.getTotalToursCompleted())
            .totalSpent(p.getTotalSpent())
            .createdDate(p.getCreatedDate() != null
                ? p.getCreatedDate().atOffset(ZoneOffset.UTC) : null)
            .lastModifiedDate(p.getLastModifiedDate() != null
                ? p.getLastModifiedDate().atOffset(ZoneOffset.UTC) : null)
            .build();
    }

    public CustomerSummaryResponse toSummaryResponse(CustomerProfile p) {
        return CustomerSummaryResponse.builder()
            .id(p.getId())
            .customerId(p.getCustomerId())
            .firstName(p.getFirstName())
            .lastName(p.getLastName())
            .email(p.getEmail())
            .phoneNumber(p.getPhoneNumber())
            .country(p.getCountry())
            .photoUrl(p.getPhotoUrl())
            .totalToursCompleted(p.getTotalToursCompleted() != null
                ? p.getTotalToursCompleted() : 0)
            .createdDate(p.getCreatedDate() != null
                ? p.getCreatedDate().atOffset(ZoneOffset.UTC) : null)
            .build();
    }

    public TravelDocumentResponse toDocumentResponse(TravelDocument d) {
        boolean expired      = d.isExpired();
        boolean expiringSoon = !expired && d.isExpiringSoon(6);

        String expiryWarning = null;
        if (expired) {
            expiryWarning = "This document expired on " + d.getExpiryDate()
                + ". Please update before booking.";
        } else if (expiringSoon && d.getExpiryDate() != null) {
            long months = java.time.temporal.ChronoUnit.MONTHS.between(
                LocalDate.now(), d.getExpiryDate());
            expiryWarning = "This document expires in " + months
                + " month(s). Some destinations require 6 months validity.";
        }

        return TravelDocumentResponse.builder()
            .id(d.getId())
            .documentType(d.getDocumentType())
            .documentTypeDisplayName(d.getDocumentType().getDisplayName())
            .fullName(d.getFullName())
            .documentNumber(d.getDocumentNumber())
            .nationality(d.getNationality())
            .issuingCountry(d.getIssuingCountry())
            .dateOfBirth(d.getDateOfBirth())
            .expiryDate(d.getExpiryDate())
            .label(d.getLabel() != null ? d.getLabel()
                : d.getDocumentType().getDisplayName())
            .primaryDocument(d.isPrimaryDocument())
            .expired(expired)
            .expiringSoon(expiringSoon)
            .expiryWarning(expiryWarning)
            .createdDate(d.getCreatedDate() != null
                ? d.getCreatedDate().atOffset(ZoneOffset.UTC) : null)
            .lastModifiedDate(d.getLastModifiedDate() != null
                ? d.getLastModifiedDate().atOffset(ZoneOffset.UTC) : null)
            .build();
    }
}
