package com.techStack.authSys.customer.dto.request;

import com.techStack.authSys.customer.models.DocumentType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

/**
 * Request to add a travel document to a customer's profile.
 * POST /api/customers/me/documents
 */
public record AddTravelDocumentRequest(

        @NotNull(message = "Document type is required")
        DocumentType documentType,

        @NotBlank(message = "Full name is required")
        @Size(max = 150)
        String fullName,

        @NotBlank(message = "Document number is required")
        @Size(max = 50)
        String documentNumber,

        @Size(max = 100)
        String nationality,

        @Size(max = 100)
        String issuingCountry,

        LocalDate dateOfBirth,

        LocalDate expiryDate,

        /**
         * Optional customer label — e.g. "My Passport", "Wife's ID".
         * Defaults to documentType.displayName if null.
         */
        @Size(max = 100)
        String label,

        /** Set this as the primary/default document. */
        boolean primaryDocument

) {}
