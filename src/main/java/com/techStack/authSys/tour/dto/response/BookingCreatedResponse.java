package com.techStack.authSys.tour.dto.response;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.UUID;

public record BookingCreatedResponse(
        UUID bookingId,
        String bookingReference,
        String tourName,
        LocalDate travelStartDate,
        LocalDate travelEndDate,
        String pickupLocation,
        LocalTime pickupTime,
        BigDecimal totalPrice,
        String currency
) {}