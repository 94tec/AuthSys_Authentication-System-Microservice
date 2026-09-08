package com.techStack.authSys.customer.dto.response;

import lombok.Builder;
import lombok.Data;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Lightweight customer response for staff search results and paginated lists.
 * GET /api/customers/admin/search, GET /api/customers/admin/all
 *
 * Excludes wishlist, documents, and stats to keep payload small.
 */
@Data
@Builder
public class CustomerSummaryResponse {

    private UUID   id;
    private String customerId;
    private String firstName;
    private String lastName;
    private String email;
    private String phoneNumber;
    private String country;
    private String photoUrl;
    private int    totalToursCompleted;
    private OffsetDateTime createdDate;
}
