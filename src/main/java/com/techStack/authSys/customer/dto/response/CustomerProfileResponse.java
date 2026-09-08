package com.techStack.authSys.customer.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Full customer profile response — returned to the customer and staff.
 *
 * Includes wishlist enquire-button.tsx IDs, document count, and denormalised stats.
 * Staff view (MANAGER+) gets the same shape — filtering by role
 * is handled at the controller level, not in the DTO.
 */
@Data
@Builder
public class CustomerProfileResponse {

    private UUID   id;
    private String customerId;     // Firebase UID

    // Core identity
    private String firstName;
    private String lastName;
    private String fullName;
    private String email;
    private String phoneNumber;

    // Profile
    private String    bio;
    private String    country;
    private String    photoUrl;
    private LocalDate dateOfBirth;
    private String    nationality;
    private String    dietaryNotes;

    // Preferences
    private boolean emailMarketingOptIn;
    private boolean smsOptIn;

    // Wishlist
    private List<UUID> savedTourIds;
    private int        wishlistCount;

    // Documents (summary counts only — full list via /documents endpoint)
    private int        documentCount;
    private boolean    hasPrimaryDocument;

    // Stats (denormalised)
    private Integer    totalToursCompleted;
    private BigDecimal totalSpent;

    // Audit
    private OffsetDateTime createdDate;
    private OffsetDateTime lastModifiedDate;
}
