package com.techStack.authSys.booking.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public record CreateBookingRequest(

        @NotNull(message = "Tour ID is required")
        UUID tourId,

        @NotNull(message = "Availability slot ID is required")
        UUID availabilityId,

        @NotNull(message = "Traveler count is required")
        @Min(value = 1, message = "At least one traveler is required")
        @Max(value = 50, message = "Maximum 50 travelers per booking")
        Integer travelerCount,

        @NotNull(message = "Traveler details are required")
        @Size(min = 1, message = "At least one traveler must be provided")
        @Valid
        List<TravelerRequest> travelers,

        @Size(max = 1000, message = "Special requests must not exceed 1000 characters")
        String specialRequests

) {
    public record TravelerRequest(

            @NotBlank(message = "Traveler full name is required")
            @Size(max = 255, message = "Name must not exceed 255 characters")
            String fullName,

            LocalDate dateOfBirth,

            @Size(max = 50, message = "Passport number must not exceed 50 characters")
            String passportNumber,

            @Size(max = 100, message = "Nationality must not exceed 100 characters")
            String nationality,

            @Size(max = 500, message = "Dietary notes must not exceed 500 characters")
            String dietaryNotes
    ) {}
}