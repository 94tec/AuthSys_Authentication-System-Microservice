package com.techStack.authSys.payment.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;

/**
 * Payment statistics for the admin dashboard.
 * GET /api/payments/admin/stats
 */
@Data
@Builder
public class PaymentStatsResponse {
    private long       pending;
    private long       successful;
    private long       failed;
    private long       cancelled;
    private long       refunded;
    private BigDecimal totalRevenue;     // sum of SUCCESS payments
    private long       totalAttempts;    // all payment rows
}
