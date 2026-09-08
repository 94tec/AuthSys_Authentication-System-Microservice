package com.techStack.authSys.customer.dto.response;

import com.techStack.authSys.customer.models.DocumentType;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Travel document response — returned for GET /api/customers/me/documents
 * and when adding/updating a document.
 *
 * Includes expiry warnings so the frontend can highlight expiring docs.
 */
@Data
@Builder
public class TravelDocumentResponse {

    private UUID         id;
    private DocumentType documentType;
    private String       documentTypeDisplayName;
    private String       fullName;
    private String       documentNumber;
    private String       nationality;
    private String       issuingCountry;
    private LocalDate    dateOfBirth;
    private LocalDate    expiryDate;
    private String       label;
    private boolean      primaryDocument;

    // Computed warnings — set by CustomerMapper
    private boolean      expired;
    private boolean      expiringSoon;        // within 6 months
    private String       expiryWarning;       // human-readable message or null

    private OffsetDateTime createdDate;
    private OffsetDateTime lastModifiedDate;
}
