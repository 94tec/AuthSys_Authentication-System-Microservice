package com.techStack.authSys.notification.dto.response;

import com.techStack.authSys.notification.models.NotificationChannel;
import com.techStack.authSys.notification.models.NotificationStatus;
import com.techStack.authSys.notification.models.NotificationType;
import lombok.Builder;
import lombok.Data;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Notification log entry response.
 * Returned by GET /api/notifications/me and admin endpoints.
 * Body field intentionally excluded — can be large HTML, not needed in lists.
 */
@Data
@Builder
public class NotificationLogResponse {
    private UUID                id;
    private String              customerId;
    private NotificationType    notificationType;
    private String              notificationTypeDisplayName;
    private NotificationChannel channel;
    private NotificationStatus  status;
    private String              statusDescription;
    private String              subject;              // email only
    private UUID                correlationId;
    private String              referenceId;
    private String              referenceType;
    private String              providerMessageId;
    private int                 attempts;
    private String              errorMessage;         // staff/admin only
    private OffsetDateTime      lastAttemptAt;
    private OffsetDateTime      deliveredAt;
    private OffsetDateTime      createdDate;
}
