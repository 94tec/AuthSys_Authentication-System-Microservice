package com.techStack.authSys.tour.services;

import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.tour.dto.response.RevenueDashboardResponse;
import com.techStack.authSys.tour.dto.response.RevenueSummary;
import com.techStack.authSys.tour.repository.EnquiryQuoteRepository;
import com.techStack.authSys.tour.repository.TourEnquiryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAdjusters;

@Slf4j
@Service
@RequiredArgsConstructor
public class RevenueDashboardService {

    private final BookingRepository bookingRepository;
    private final EnquiryQuoteRepository enquiryQuoteRepository;
    private final TourEnquiryRepository enquiryRepository;

    private static final ZoneId ZONE = ZoneOffset.UTC; // adjust if you're on a fixed business timezone, e.g. Africa/Nairobi

    @Transactional(readOnly = true)
    public Mono<RevenueDashboardResponse> getRevenueDashboard() {
        return Mono.fromCallable(() -> {
            Instant now = Instant.now();
            LocalDate today = LocalDate.now(ZONE);

            Instant startOfToday = today.atStartOfDay(ZONE).toInstant();
            Instant startOfWeek = today.with(TemporalAdjusters.previousOrSame(java.time.DayOfWeek.MONDAY))
                    .atStartOfDay(ZONE).toInstant();
            Instant startOfMonth = today.withDayOfMonth(1).atStartOfDay(ZONE).toInstant();
            Instant startOfLastMonth = today.minusMonths(1).withDayOfMonth(1).atStartOfDay(ZONE).toInstant();
            Instant endOfLastMonth = startOfMonth;

            RevenueSummary todaySummary = summaryFor(startOfToday, now);
            RevenueSummary weekSummary = summaryFor(startOfWeek, now);
            RevenueSummary monthSummary = summaryFor(startOfMonth, now);
            RevenueSummary lastMonthSummary = summaryFor(startOfLastMonth, endOfLastMonth);

            double momChange = percentChange(
                    lastMonthSummary.actualRevenue(),
                    monthSummary.actualRevenue()
            );

            return new RevenueDashboardResponse(
                    todaySummary,
                    weekSummary,
                    monthSummary,
                    lastMonthSummary,
                    momChange
            );
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private RevenueSummary summaryFor(Instant from, Instant to) {
        BigDecimal actualRevenue = nullToZero(bookingRepository.getCompletedRevenue(from, to));
        long toursSold = bookingRepository.countCompletedBookings(from, to);

        BigDecimal expectedRevenue = nullToZero(enquiryQuoteRepository.getOpenPipelineValue(from, to));
        long enquiryCount = enquiryRepository.countCreatedBetween(from, to);

        return new RevenueSummary(actualRevenue, expectedRevenue, toursSold, enquiryCount);
    }

    private BigDecimal nullToZero(BigDecimal value) {
        return value == null ? BigDecimal.ZERO : value;
    }

    private double percentChange(BigDecimal previous, BigDecimal current) {
        if (previous == null || previous.compareTo(BigDecimal.ZERO) == 0) {
            return current != null && current.compareTo(BigDecimal.ZERO) > 0 ? 100.0 : 0.0;
        }
        return current.subtract(previous)
                .divide(previous, 4, RoundingMode.HALF_UP)
                .multiply(BigDecimal.valueOf(100))
                .doubleValue();
    }
}