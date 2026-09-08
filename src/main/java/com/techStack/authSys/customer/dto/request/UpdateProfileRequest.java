package com.techStack.authSys.customer.dto.request;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

/**
 * Patch-style profile update — only non-null fields applied.
 * PUT /api/customers/me
 *
 * firstName, lastName, email are intentionally excluded —
 * those are managed by the auth system (Firebase profile).
 * A sync from auth → profile happens on login via CustomerService.syncFromAuth().
 */
public record UpdateProfileRequest(

        @Pattern(
            regexp = "^2547\\d{8}$",
            message = "Phone number must be in format 2547XXXXXXXX"
        )
        String phoneNumber,

        @Size(max = 500, message = "Bio must be under 500 characters")
        String bio,

        @Size(max = 100, message = "Country must be under 100 characters")
        String country,

        @Size(max = 500, message = "Photo URL must be under 500 characters")
        String photoUrl,

        LocalDate dateOfBirth,

        @Size(max = 100)
        String nationality,

        @Size(max = 500)
        String dietaryNotes,

        Boolean emailMarketingOptIn,
        Boolean smsOptIn

) {}
