package com.techStack.authSys.customer.dto.request;

import jakarta.validation.constraints.Size;

import java.time.LocalDate;

/**
 * Patch a saved travel document.
 * PUT /api/customers/me/documents/{id}
 *
 * documentType and documentNumber are immutable — delete and re-add to change.
 * Only non-null fields are applied.
 */
public record UpdateTravelDocumentRequest(

        @Size(max = 150)
        String fullName,

        @Size(max = 100)
        String nationality,

        @Size(max = 100)
        String issuingCountry,

        LocalDate dateOfBirth,
        LocalDate expiryDate,

        @Size(max = 100)
        String label

) {}
