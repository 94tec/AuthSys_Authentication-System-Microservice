package com.techStack.authSys.notification.dto.response;

import lombok.Builder;
import lombok.Data;

/**
 * Notification delivery health stats — admin dashboard.
 * GET /api/notifications/admin/stats
 */
@Data
@Builder
public class NotificationStatsResponse {
    private long pending;
    private long sent;
    private long delivered;
    private long failed;
    private long skipped;
    private long recentFailures;   // last 24 hours — health signal
}
