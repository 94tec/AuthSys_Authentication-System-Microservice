package com.techStack.authSys.service.registration;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.*;
import com.techStack.authSys.models.security.RegistrationThrottleRecord;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static com.techStack.authSys.constants.SecurityConstants.THROTTLE_COLLECTION;

/**
 * Registration Throttle Service
 *
 * Implements rate limiting for registration attempts.
 * Protects against brute force and spam attacks.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationThrottleService {

    /* =========================
       Dependencies
       ========================= */

    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final MetricsService metricsService;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${security.registration.max-attempts-per-hour:5}")
    private int maxAttemptsPerHour;

    @Value("${security.registration.max-attempts-per-day:20}")
    private int maxAttemptsPerDay;

    @Value("${security.registration.block-duration-hours:24}")
    private int blockDurationHours;

    @Value("${security.registration.allow-on-error:true}")
    private boolean allowOnError;

    /* =========================
       Rate Limit Check
       ========================= */

    /**
     * Check if IP address has exceeded rate limits
     */
    public Mono<Void> checkRateLimit(String ipAddress) {
        String normalizedIp = normalizeIp(ipAddress);

        return Mono.defer(() -> {
            Instant now = clock.instant();
            Instant oneHourAgo = now.minus(1, ChronoUnit.HOURS);
            Instant oneDayAgo = now.minus(24, ChronoUnit.HOURS);

            return getThrottleRecord(normalizedIp)
                    .switchIfEmpty(createNewThrottleRecord(normalizedIp))
                    .flatMap(record -> {
                        if (isIpBlocked(record, now)) {
                            return handleBlockedIp(normalizedIp);
                        }

                        if (hasExceededLimits(record)) {
                            return blockIpAddress(normalizedIp, record)
                                    .then(Mono.error(new RegistrationThrottleException(
                                            "Too many registration attempts")));
                        }

                        return updateThrottleCounts(normalizedIp, record, oneHourAgo, oneDayAgo);
                    })
                    .onErrorResume(e -> handleThrottleError(normalizedIp, e));
        }).subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       Throttle Record Operations
       ========================= */

    /**
     * Get throttle record from Firestore
     */
    private Mono<RegistrationThrottleRecord> getThrottleRecord(String ipAddress) {
        DocumentReference docRef = firestore.collection(THROTTLE_COLLECTION).document(ipAddress);

        return Mono.fromCallable(() -> docRef.get().get())
                .map(documentSnapshot -> {
                    if (documentSnapshot.exists()) {
                        RegistrationThrottleRecord record =
                                documentSnapshot.toObject(RegistrationThrottleRecord.class);

                        if (record != null) {
                            return record.withIpAddress(ipAddress);
                        }
                    }
                    return null;
                })
                .onErrorResume(e -> {
                    log.error("Failed to get throttle record for {}: {}", ipAddress, e.getMessage());
                    return allowOnError ? Mono.empty() : Mono.error(e);
                });
    }

    /**
     * Create new throttle record
     */
    private Mono<RegistrationThrottleRecord> createNewThrottleRecord(String ipAddress) {
        Instant now = clock.instant();

        RegistrationThrottleRecord record = RegistrationThrottleRecord.builder()
                .ipAddress(ipAddress)
                .hourlyCount(0)
                .dailyCount(0)
                .lastAttempt(Date.from(now))
                .blockedUntil(null)
                .build();

        return Mono.fromCallable(() -> {
            firestore.collection(THROTTLE_COLLECTION)
                    .document(ipAddress)
                    .set(record)
                    .get();
            return record;
        });
    }

    /**
     * Update throttle counts
     */
    private Mono<Void> updateThrottleCounts(
            String ipAddress,
            RegistrationThrottleRecord record,
            Instant oneHourAgo,
            Instant oneDayAgo
    ) {
        Instant now = clock.instant();

        return Mono.fromCallable(() -> {
                    RegistrationThrottleRecord updatedRecord = record
                            .withLastAttempt(Date.from(now))
                            .withHourlyCount(shouldResetCount(record.getLastAttempt(), oneHourAgo) ?
                                    1 : record.getHourlyCount() + 1)
                            .withDailyCount(shouldResetCount(record.getLastAttempt(), oneDayAgo) ?
                                    1 : record.getDailyCount() + 1);

                    return firestore.collection(THROTTLE_COLLECTION)
                            .document(ipAddress)
                            .set(updatedRecord)
                            .get();
                })
                .doOnSuccess(v -> log.debug("Updated throttle counts for {}", ipAddress))
                .then();
    }

    /**
     * Block IP address
     */
    private Mono<Void> blockIpAddress(String ipAddress, RegistrationThrottleRecord record) {
        Instant now = clock.instant();
        Instant blockUntil = now.plus(blockDurationHours, ChronoUnit.HOURS);

        RegistrationThrottleRecord updatedRecord = record.withBlockedUntil(Date.from(blockUntil));

        return Mono.fromCallable(() -> firestore.collection(THROTTLE_COLLECTION)
                        .document(ipAddress)
                        .set(updatedRecord)
                        .get())
                .doOnSuccess(v -> {
                    log.warn("🚫 IP address blocked: {}", ipAddress);
                    auditLogService.logSystemEvent(
                            "REGISTRATION_IP_BLOCKED",
                            "IP " + ipAddress + " blocked due to excessive registration attempts"
                    );
                    metricsService.incrementCounter("registration.ip_blocked", "ip", ipAddress);
                })
                .then()
                .onErrorResume(e -> {
                    log.error("Failed to block IP {}: {}", ipAddress, e.getMessage());
                    return Mono.empty();
                });
    }

    /* =========================
       Validation Helpers
       ========================= */

    /**
     * Check if IP is currently blocked
     */
    private boolean isIpBlocked(RegistrationThrottleRecord record, Instant now) {
        return record.getBlockedUntil() != null &&
                record.getBlockedUntil().after(Date.from(now));
    }

    /**
     * Check if limits exceeded
     */
    private boolean hasExceededLimits(RegistrationThrottleRecord record) {
        return record.getHourlyCount() >= maxAttemptsPerHour ||
                record.getDailyCount() >= maxAttemptsPerDay;
    }

    /**
     * Check if count should be reset
     */
    private boolean shouldResetCount(Date lastAttempt, Instant cutoff) {
        return lastAttempt == null || lastAttempt.before(Date.from(cutoff));
    }

    /**
     * Handle blocked IP attempt
     */
    private Mono<Void> handleBlockedIp(String ipAddress) {
        log.warn("🚫 Blocked IP attempt: {}", ipAddress);

        auditLogService.logSystemEvent(
                "REGISTRATION_BLOCKED",
                "Blocked registration attempt from " + ipAddress
        );

        metricsService.incrementCounter("registration.blocked_attempt", "ip", ipAddress);

        return Mono.error(new RegistrationThrottleException(
                "Too many registration attempts. Try again later."));
    }

    /**
     * Handle throttle errors
     */
    private Mono<Void> handleThrottleError(String ipAddress, Throwable e) {
        if (e instanceof RegistrationThrottleException) {
            return Mono.error(e);
        }

        log.error("Error processing rate limit for IP {}: {}", ipAddress, e.getMessage());
        metricsService.incrementCounter("rate_limit.error", "ip", ipAddress);

        return allowOnError ? Mono.empty() : Mono.error(e);
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Normalize IP address
     */
    private String normalizeIp(String ip) {
        return "0:0:0:0:0:0:0:1".equals(ip) ? "127.0.0.1" : ip;
    }

    /* =========================
       Cleanup Job
       ========================= */

    /**
     * Cleanup old throttle records (runs daily at 3 AM)
     */
    @Scheduled(cron = "${security.registration.cleanup-cron:0 0 3 * * *}")
    public void cleanupOldThrottleRecords() {
        try {
            Instant cutoff = clock.instant().minus(30, ChronoUnit.DAYS);

            ApiFuture<QuerySnapshot> future = firestore.collection(THROTTLE_COLLECTION)
                    .whereLessThan("lastAttempt", Date.from(cutoff))
                    .get();

            List<QueryDocumentSnapshot> docs = future.get().getDocuments();

            if (!docs.isEmpty()) {
                WriteBatch batch = firestore.batch();
                docs.forEach(doc -> batch.delete(doc.getReference()));
                batch.commit().get();

                log.info("✅ Cleaned up {} old throttle records", docs.size());
                metricsService.incrementCounter("registration.throttle_cleanup",
                        "count", String.valueOf(docs.size()));
            }
        } catch (Exception e) {
            log.error("Failed to clean up throttle records: {}", e.getMessage());

            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /* =========================
       Exception
       ========================= */

    /**
     * Registration throttle exception
     */
    public static class RegistrationThrottleException extends RuntimeException {
        public RegistrationThrottleException(String message) {
            super(message);
        }
    }
}