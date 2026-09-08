package com.techStack.authSys.notification.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Delivery status of a single NotificationLog row.
 *
 * PENDING   → queued, not yet sent (retry window)
 * SENT      → accepted by the channel provider (Brevo / Africa's Talking)
 * DELIVERED → provider confirmed delivery (where supported)
 * FAILED    → provider rejected or max retries exceeded
 * SKIPPED   → customer opted out or channel not available for this type
 */
@Getter
@RequiredArgsConstructor
public enum NotificationStatus {
    PENDING("Queued for delivery"),
    SENT("Accepted by provider"),
    DELIVERED("Confirmed delivered"),
    FAILED("Delivery failed"),
    SKIPPED("Skipped — opted out or not applicable");

    private final String description;
}
