package com.techStack.authSys.service.registration;

import com.techStack.authSys.event.UserRegisteredEvent;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.observability.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Registration Metrics Service
 *
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
    private final Clock clock;

    /**
     * Record all metrics and audit logs for successful registration
     */
    public void recordSuccessfulRegistration(
            User user,
            String ipAddress,
            String deviceFingerprint,
            long durationMs
    ) {
        Instant now = clock.instant();

        // Audit log
        logAuditTrail(user, ipAddress, deviceFingerprint, now);

        // Cache email (best-effort)
        cacheRegisteredEmail(user.getEmail());

        // Record metrics
        recordMetrics(user, durationMs);

        // Publish domain event
        publishRegistrationEvent(user, ipAddress);
    }

    /**
     * Create audit log entry for registration
     */
    private void logAuditTrail(
            User user,
            String ipAddress,
            String deviceFingerprint,
            Instant now
    ) {
        try {
            String details = String.format(
                    "User registered - Status: %s, Roles: %s, DeviceFingerprint: %s",
                    user.getStatus(),
                    user.getRoleNames(),
                    deviceFingerprint
            );

            auditLogService.logAudit(
                    user,
                    ActionType.REGISTRATION,
                    details,
                    ipAddress
            );

            log.debug("✅ Audit log created for registration: {}", user.getEmail());

        } catch (Exception e) {
            log.warn("Failed to log audit for {}: {}", user.getEmail(), e.getMessage());
        }
    }

    /**
     * Cache registered email in Redis (fire-and-forget)
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
     * Record registration metrics
     */
    private void recordMetrics(User user, long durationMs) {
        try {
            // Success counter
            metricsService.incrementCounter(
                    "user.registration.success",
                    String.valueOf(Map.of(
                            "status", user.getStatus().name(),
                            "has_roles", String.valueOf(!user.getRoleNames().isEmpty())
                    ))
            );

            // Duration timer
            metricsService.recordTimer(
                    "user.registration.time",
                    Duration.ofMillis(durationMs)
            );

            // Role-specific metrics
            if (user.getRoleNames() != null) {
                user.getRoleNames().forEach(role ->
                        metricsService.incrementCounter(
                                "user.registration.by_role",
                                "role", role
                        )
                );
            }

            log.debug("✅ Metrics recorded for registration: {}", user.getEmail());

        } catch (Exception e) {
            log.warn("Failed to record metrics for {}: {}", user.getEmail(), e.getMessage());
        }
    }

    /**
     * Publish domain event for other subsystems
     */
    private void publishRegistrationEvent(User user, String ipAddress) {
        try {
            UserRegisteredEvent event = new UserRegisteredEvent(user, ipAddress);
            eventPublisher.publishEvent(event);

            log.debug("✅ Published UserRegisteredEvent for: {}", user.getEmail());

        } catch (Exception e) {
            log.warn("Failed to publish UserRegisteredEvent for {}: {}",
                    user.getEmail(), e.getMessage());
        }
    }

    /**
     * Record registration failure
     */
    public void recordRegistrationFailure(String email, String reason) {
        try {
            metricsService.incrementCounter(
                    "user.registration.failure",
                    String.valueOf(Map.of(
                            "reason", reason,
                            "email_domain", extractDomain(email)
                    ))
            );

            log.debug("Recorded registration failure for: {} - Reason: {}", email, reason);

        } catch (Exception e) {
            log.warn("Failed to record failure metrics for {}: {}", email, e.getMessage());
        }
    }

    /**
     * Extract domain from email
     */
    private String extractDomain(String email) {
        if (email == null || !email.contains("@")) {
            return "unknown";
        }
        return email.substring(email.indexOf("@") + 1);
    }
}