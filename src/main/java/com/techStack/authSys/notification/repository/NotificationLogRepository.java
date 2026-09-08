package com.techStack.authSys.notification.repository;

import com.techStack.authSys.notification.models.NotificationChannel;
import com.techStack.authSys.notification.models.NotificationLog;
import com.techStack.authSys.notification.models.NotificationStatus;
import com.techStack.authSys.notification.models.NotificationType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Repository
public interface NotificationLogRepository extends JpaRepository<NotificationLog, UUID> {

    // ── Customer-scoped ───────────────────────────────────────────────────────

    Page<NotificationLog> findByCustomerIdOrderByCreatedDateDesc(
            String customerId, Pageable pageable);

    List<NotificationLog> findByCustomerIdAndChannelOrderByCreatedDateDesc(
            String customerId, NotificationChannel channel);

    // ── Reference-based (booking/payment level) ───────────────────────────────

    List<NotificationLog> findByReferenceIdOrderByCreatedDateDesc(String referenceId);

    List<NotificationLog> findByCorrelationId(UUID correlationId);

    // ── Retry queue ───────────────────────────────────────────────────────────

    @Query("""
            SELECT n FROM NotificationLog n
            WHERE (n.status = com.techStack.authSys.notification.models.NotificationStatus.FAILED
                OR n.status = com.techStack.authSys.notification.models.NotificationStatus.PENDING)
              AND n.attempts   < :maxRetries
              AND n.createdDate >= :cutoff
            ORDER BY n.lastAttemptAt ASC NULLS FIRST
            """)
    List<NotificationLog> findRetryable(
            @Param("maxRetries") int maxRetries,
            @Param("cutoff")     Instant cutoff);

    // ── Provider callback matching ────────────────────────────────────────────

    java.util.Optional<NotificationLog> findByProviderMessageId(String providerMessageId);

    // ── Admin ─────────────────────────────────────────────────────────────────

    Page<NotificationLog> findAllByOrderByCreatedDateDesc(Pageable pageable);

    Page<NotificationLog> findByNotificationTypeAndStatusOrderByCreatedDateDesc(
            NotificationType type, NotificationStatus status, Pageable pageable);

    // ── Stats ─────────────────────────────────────────────────────────────────

    long countByStatus(NotificationStatus status);

    long countByNotificationTypeAndStatus(NotificationType type, NotificationStatus status);

    @Query("""
            SELECT COUNT(n) FROM NotificationLog n
            WHERE n.status      = com.techStack.authSys.notification.models.NotificationStatus.FAILED
              AND n.createdDate >= :since
            """)
    long countRecentFailures(@Param("since") Instant since);
}