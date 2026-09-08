package com.techStack.authSys.tour.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.UUID;

public record CreateBookingFromPaymentRequest(
        @NotNull UUID availabilityId,
        String pickupLocation,
        LocalTime pickupTime,
        String specialInstructions,
        @NotEmpty @Valid List<TravelerInfo> travelers
) {
    public record TravelerInfo(
            @NotBlank String fullName,
            LocalDate dateOfBirth,
            String passportNumber,
            String nationality,
            String dietaryNotes
    ) {}
}