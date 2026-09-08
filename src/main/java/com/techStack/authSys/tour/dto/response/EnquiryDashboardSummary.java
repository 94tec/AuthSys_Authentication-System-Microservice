package com.techStack.authSys.tour.dto.response;

public record EnquiryDashboardSummary(
        long newCount, long contactedCount, long quotedCount,
        long convertedCount, long completedCount, long lostCount,
        long unassignedCount, long overdueFollowUpCount,
        long upcomingDeparturesCount, long pendingAppreciationCount
) {}