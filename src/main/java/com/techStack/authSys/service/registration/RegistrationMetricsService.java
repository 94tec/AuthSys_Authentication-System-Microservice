package com.techStack.authSys.service.registration;

import com.techStack.authSys.event.UserRegisteredEvent;
import com.techStack.authSys.models.ActionType;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.service.AuditLogService;
import com.techStack.authSys.service.RedisUserCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;

/**
 * Handles metrics, auditing, and event publishing for registration events.
 * Centralizes all observability concerns.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationMetricsService {

    private final MetricsService metricsService;
    private final AuditLogService auditLogService;
    private final RedisUserCacheService redisCacheService;
    private final ApplicationEventPublisher eventPublisher;

    /**
     * Records all metrics and audit logs for a successful registration.
     */
    public void recordSuccessfulRegistration(
            User user,
            String ipAddress,
            String deviceFingerprint,
            long durationMs) {

        // Audit log
        logAuditTrail(user, ipAddress, deviceFingerprint);

        // Cache email (best-effort)
        cacheRegisteredEmail(user.getEmail());

        // Record metrics
        recordMetrics(durationMs);

        // Publish domain event
        publishRegistrationEvent(user, ipAddress);
    }

    /**
     * Creates an audit log entry for the registration.
     */
    private void logAuditTrail(User user, String ipAddress, String deviceFingerprint) {
        try {
            auditLogService.logAudit(
                    user,
                    ActionType.REGISTRATION,
                    String.format("User registered. DeviceFingerprint: %s", deviceFingerprint),
                    ipAddress
            );
        } catch (Exception e) {
            log.warn("Failed to log audit for {}: {}", user.getEmail(), e.getMessage());
        }
    }

    /**
     * Caches the registered email in Redis (fire-and-forget).
     */
    private void cacheRegisteredEmail(String email) {
        try {
            redisCacheService.cacheRegisteredEmail(email)
                    .subscribeOn(Schedulers.boundedElastic())
                    .doOnSuccess(v -> log.debug("Cached registered email: {}", email))
                    .doOnError(e -> log.warn("Failed to cache email {}: {}",
                            email, e.getMessage()))
                    .subscribe();
        } catch (Exception e) {
            log.warn("Cache operation failed for {}: {}", email, e.getMessage());
        }
    }

    /**
     * Records registration metrics for monitoring.
     */
    private void recordMetrics(long durationMs) {
        try {
            metricsService.incrementCounter("user.registration.success");
            metricsService.recordTimer("user.registration.time", Duration.ofMillis(durationMs));
        } catch (Exception e) {
            log.warn("Failed to record metrics: {}", e.getMessage());
        }
    }

    /**
     * Publishes a domain event for other subsystems to consume.
     */
    private void publishRegistrationEvent(User user, String ipAddress) {
        try {
            eventPublisher.publishEvent(new UserRegisteredEvent(user, ipAddress));
        } catch (Exception e) {
            log.warn("Failed to publish UserRegisteredEvent for {}: {}",
                    user.getEmail(), e.getMessage());
        }
    }
}
