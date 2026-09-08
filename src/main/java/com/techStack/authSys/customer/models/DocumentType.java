package com.techStack.authSys.customer.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Type of travel document stored in TravelDocument.
 *
 * Used to determine what fields are required and what warnings to show.
 * PASSPORT is required for international tours (e.g. cross-border safaris).
 * NATIONAL_ID is sufficient for domestic Kenyan tours.
 */
@Getter
@RequiredArgsConstructor
public enum DocumentType {

    PASSPORT("Passport",           true),
    NATIONAL_ID("National ID",     false),
    ALIEN_CARD("Alien Card",       false),
    BIRTH_CERTIFICATE("Birth Certificate", false),  // for minors
    OTHER("Other",                 false);

    private final String displayName;

    /**
     * Whether an expiry date is mandatory for this document type.
     * Passports always have expiry dates. National IDs vary by country.
     */
    private final boolean expiryRequired;
}
