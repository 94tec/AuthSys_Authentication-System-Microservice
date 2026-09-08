package com.techStack.authSys.tour.dto.pdf;

import java.math.BigDecimal;
import java.time.LocalDate;

public record QuotePdfData(
        String quoteId,
        String customerName,
        String customerEmail,
        String tourName,
        String destination,
        String country,
        int durationDays,
        int durationNights,
        LocalDate preferredDate,
        int adultCount,
        int childCount,
        BigDecimal pricePerAdult,
        BigDecimal pricePerChild,
        BigDecimal totalPrice,
        String currency,
        LocalDate validUntil,
        String inclusionsNote,
        String verificationUrl // encoded into the QR code
) {}