package com.techStack.authSys.models;

import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.util.FirestoreUtil;
import lombok.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

@Getter
@ToString
@EqualsAndHashCode
@Builder(toBuilder = true)
@NoArgsConstructor(force = true)
@AllArgsConstructor(access = AccessLevel.PRIVATE) // Ensures immutability
public class RegistrationThrottleRecord {
    private static final Logger logger = LoggerFactory.getLogger(RegistrationThrottleRecord.class);
    private static final String THROTTLE_COLLECTION = "throttleRecords";

    private final String ipAddress;
    private final int hourlyCount;
    private final int dailyCount;
    private final Date lastAttempt;
    @Nullable
    private final Date blockedUntil;

    public static Mono<RegistrationThrottleRecord> getThrottleRecord(Firestore firestore, String ipAddress) {
        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(firestore.collection(THROTTLE_COLLECTION)
                        .document(ipAddress)
                        .get()))
                .flatMap(document -> {
                    if (!document.exists()) {
                        logger.warn("No throttle record found for {}", ipAddress);
                        return Mono.empty();
                    }

                    Map<String, Object> data = document.getData();
                    if (data == null) {
                        return Mono.empty();
                    }

                    return Mono.just(RegistrationThrottleRecord.builder()
                            .ipAddress(ipAddress)
                            .hourlyCount(((Number) data.getOrDefault("hourlyCount", 0)).intValue())
                            .dailyCount(((Number) data.getOrDefault("dailyCount", 0)).intValue())
                            .lastAttempt((Date) data.getOrDefault("lastAttempt", new Date(0)))
                            .blockedUntil((Date) data.get("blockedUntil"))
                            .build());
                })
                .onErrorResume(e -> {
                    logger.error("Failed to fetch throttle record for {}: {}", ipAddress, e.getMessage());
                    return Mono.empty();
                });
    }

    public boolean isBlocked() {
        return blockedUntil != null && blockedUntil.after(new Date());
    }

    public boolean hasExceededLimits(int maxHourly, int maxDaily) {
        return hourlyCount >= maxHourly || dailyCount >= maxDaily;
    }

    public Instant getLastAttemptInstant() {
        return lastAttempt.toInstant();
    }

    @Nullable
    public Instant getBlockedUntilInstant() {
        return blockedUntil != null ? blockedUntil.toInstant() : null;
    }

    public RegistrationThrottleRecord withAttempt(Date newAttemptTime) {
        return toBuilder()
                .lastAttempt(newAttemptTime)
                .hourlyCount(hourlyCount + 1)
                .dailyCount(dailyCount + 1)
                .build();
    }

    public RegistrationThrottleRecord resetHourlyCount() {
        return toBuilder().hourlyCount(0).build();
    }

    public RegistrationThrottleRecord resetDailyCount() {
        return toBuilder().dailyCount(0).build();
    }

    public RegistrationThrottleRecord withLastAttempt(Date newLastAttempt) {
        Objects.requireNonNull(newLastAttempt, "Last attempt date cannot be null");
        return toBuilder().lastAttempt(new Date(newLastAttempt.getTime())).build();
    }

    public RegistrationThrottleRecord withHourlyCount(int newHourlyCount) {
        return toBuilder().hourlyCount(newHourlyCount).build();
    }

    public RegistrationThrottleRecord withDailyCount(int newDailyCount) {
        return toBuilder().dailyCount(newDailyCount).build();
    }

    public RegistrationThrottleRecord withBlockedUntil(@Nullable Date newBlockedUntil) {
        return toBuilder().blockedUntil(newBlockedUntil != null ? new Date(newBlockedUntil.getTime()) : null).build();
    }

    public RegistrationThrottleRecord withIpAddress(String newIpAddress) {
        Objects.requireNonNull(newIpAddress, "IP address cannot be null");
        return toBuilder().ipAddress(newIpAddress).build();
    }

    public RegistrationThrottleRecord withNewAttempt(Date attemptTime) {
        Objects.requireNonNull(attemptTime, "Attempt time cannot be null");
        return toBuilder()
                .lastAttempt(new Date(attemptTime.getTime()))
                .hourlyCount(this.hourlyCount + 1)
                .dailyCount(this.dailyCount + 1)
                .build();
    }
}
