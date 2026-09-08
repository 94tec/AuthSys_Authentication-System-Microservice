package com.techStack.authSys.tour.dto.response;

import java.math.BigDecimal;

public record RevenueSummary(
        BigDecimal actualRevenue,
        BigDecimal expectedRevenue,
        long toursSold,
        long enquiryCount
) {}
