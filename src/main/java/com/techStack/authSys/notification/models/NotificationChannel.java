package com.techStack.authSys.notification.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Delivery channel for a notification.
 *
 * EMAIL    — Brevo (existing BrevoEmailService, extended here)
 * SMS      — Africa's Talking (primary Kenya coverage, USSD fallback)
 * WHATSAPP — Africa's Talking WhatsApp Business API
 *            (same number as SMS — customer chooses channel)
 * IN_APP   — stored in notification_log, surfaced via
 *            GET /api/notifications/me (Phase 3 frontend bell icon)
 */
@Getter
@RequiredArgsConstructor
public enum NotificationChannel {
    EMAIL("Email"),
    SMS("SMS"),
    WHATSAPP("WhatsApp"),
    IN_APP("In-App");

    private final String displayName;
}
