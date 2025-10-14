package com.techStack.authSys.service;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.*;
import com.techStack.authSys.models.RegistrationThrottleRecord;
import com.techStack.authSys.repository.MetricsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationThrottleService {
    private static final String THROTTLE_COLLECTION = "registration_throttle";
    private static final RegistrationThrottleRecord EMPTY_RECORD = RegistrationThrottleRecord.builder()
            .hourlyCount(0)
            .dailyCount(0)
            .lastAttempt(new Date(0))
            .blockedUntil(null)
            .build();

    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final MetricsService metricsService;

    @Value("${security.registration.max-attempts-per-hour:5}")
    private int maxAttemptsPerHour;

    @Value("${security.registration.max-attempts-per-day:20}")
    private int maxAttemptsPerDay;

    @Value("${security.registration.block-duration-hours:24}")
    private int blockDurationHours;

    @Value("${security.registration.allow-on-error:true}")
    private boolean allowOnError;

    public Mono<Void> checkRateLimit(String ipAddress) {
        // Normalize IP address (convert IPv6 localhost to IPv4)
        String normalizedIp = normalizeIp(ipAddress);

        return Mono.defer(() -> {
            Instant now = Instant.now();
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
                                    .then(Mono.error(new RegistrationThrottleException("Too many registration attempts")));
                        }
                        return updateThrottleCounts(normalizedIp, record, oneHourAgo, oneDayAgo);
                    })
                    .onErrorResume(e -> {
                        log.error("Rate limit check error for IP {}: {}", normalizedIp, e.getMessage());
                        // Fail open - allow registration if throttle service fails
                        return Mono.empty();
                    });
        }).subscribeOn(Schedulers.boundedElastic());
    }


    private Mono<RegistrationThrottleRecord> createNewThrottleRecord(String ipAddress) {
        RegistrationThrottleRecord record = RegistrationThrottleRecord.builder()
                .ipAddress(ipAddress)
                .hourlyCount(0)
                .dailyCount(0)
                .lastAttempt(new Date())
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

// Helper methods:

    private String normalizeIp(String ip) {
        return "0:0:0:0:0:0:0:1".equals(ip) ? "127.0.0.1" : ip;
    }

    private RegistrationThrottleRecord createEmptyRecord(String ip) {
        return RegistrationThrottleRecord.builder()
                .ipAddress(ip)
                .hourlyCount(0)
                .dailyCount(0)
                .lastAttempt(new Date(0))
                .blockedUntil(null)
                .build();
    }

    private Mono<Void> handleThrottleError(String ipAddress, Throwable e) {
        if (e instanceof RegistrationThrottleException) {
            // Already logged in the main flow
            return Mono.error(e);
        }

        log.error("Error processing rate limit for IP {}: {}", ipAddress, e.getMessage());
        metricsService.incrementCounter("rate_limit.error", "ip", ipAddress);

        // Fail open (allow) when there are service errors
        return allowOnError ? Mono.empty() : Mono.error(e);
    }

    private boolean isIpBlocked(RegistrationThrottleRecord record, Instant now) {
        return Optional.ofNullable(record.getBlockedUntil())
                .map(blockedUntil -> blockedUntil.after(Date.from(now)))
                .orElse(false);
    }

    private boolean hasExceededLimits(RegistrationThrottleRecord record) {
        return record.getHourlyCount() >= maxAttemptsPerHour ||
                record.getDailyCount() >= maxAttemptsPerDay;
    }

    private Mono<RegistrationThrottleRecord> getThrottleRecord(String ipAddress) {
        DocumentReference docRef = firestore.collection(THROTTLE_COLLECTION).document(ipAddress);
        return Mono.fromCallable(() -> docRef.get().get())
                .map(documentSnapshot -> {
                    if (documentSnapshot.exists()) {
                        RegistrationThrottleRecord record = documentSnapshot.toObject(RegistrationThrottleRecord.class);
                        return Optional.ofNullable(record)
                                .map(r -> r.withIpAddress(ipAddress))
                                .orElseGet(() -> EMPTY_RECORD.withIpAddress(ipAddress));
                    }
                    return null;
                })
                .onErrorResume(e -> {
                    log.error("Failed to get throttle record for {}: {}", ipAddress, e.getMessage());
                    return allowOnError ? Mono.empty() : Mono.error(e);
                });
    }

    private Mono<Void> blockIpAddress(String ipAddress, RegistrationThrottleRecord record) {
        RegistrationThrottleRecord updatedRecord = record.withBlockedUntil(
                Date.from(Instant.now().plus(blockDurationHours, ChronoUnit.HOURS))
        );

        return Mono.fromCallable(() -> firestore.collection(THROTTLE_COLLECTION)
                        .document(ipAddress)
                        .set(updatedRecord)
                        .get())
                .doOnSuccess(v -> {
                    log.warn("IP address blocked: {}", ipAddress);
                    auditLogService.logSystemEvent(
                            "REGISTRATION_IP_BLOCKED",
                            "IP " + ipAddress + " blocked due to excessive registration attempts"
                    );
                })
                .then()
                .onErrorResume(e -> {
                    log.error("Failed to block IP {}: {}", ipAddress, e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Void> updateThrottleCounts(String ipAddress, RegistrationThrottleRecord record,
                                            Instant oneHourAgo, Instant oneDayAgo) {
        return Mono.fromCallable(() -> {
                    RegistrationThrottleRecord updatedRecord = record
                            .withLastAttempt(new Date())
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

    private boolean shouldResetCount(Date lastAttempt, Instant cutoff) {
        return lastAttempt == null || lastAttempt.before(Date.from(cutoff));
    }

    private Mono<Void> handleBlockedIp(String ipAddress) {
        log.warn("Blocked IP attempt: {}", ipAddress);
        auditLogService.logSystemEvent(
                "REGISTRATION_BLOCKED",
                "Blocked registration attempt from " + ipAddress
        );
        return Mono.error(new RegistrationThrottleException("Too many registration attempts. Try again later."));
    }

    @Scheduled(cron = "${security.registration.cleanup-cron:0 0 3 * * *}")
    public void cleanupOldThrottleRecords() {
        try {
            Instant cutoff = Instant.now().minus(30, ChronoUnit.DAYS);
            ApiFuture<QuerySnapshot> future = firestore.collection(THROTTLE_COLLECTION)
                    .whereLessThan("lastAttempt", Date.from(cutoff))
                    .get();

            List<QueryDocumentSnapshot> docs = future.get().getDocuments();
            if (!docs.isEmpty()) {
                WriteBatch batch = firestore.batch();
                docs.forEach(doc -> batch.delete(doc.getReference()));
                batch.commit().get();
                log.info("Cleaned up {} old throttle records", docs.size());
            }
        } catch (Exception e) {
            log.error("Failed to clean up throttle records: {}", e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public static class RegistrationThrottleException extends RuntimeException {
        public RegistrationThrottleException(String message) {
            super(message);
        }
    }
}