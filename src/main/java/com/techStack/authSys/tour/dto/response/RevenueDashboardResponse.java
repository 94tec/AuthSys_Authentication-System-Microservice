package com.techStack.authSys.tour.dto.response;

public record RevenueDashboardResponse(
        RevenueSummary today,
        RevenueSummary thisWeek,
        RevenueSummary thisMonth,
        RevenueSummary lastMonth,
        double monthOverMonthChangePercent
) {}
