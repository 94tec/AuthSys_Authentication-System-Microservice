package com.techStack.authSys.repository;

import java.time.Duration;
import java.util.Map;
import java.util.function.Supplier;

public interface MetricsService {
    void recordBlacklistEvent(String eventType, String ipAddress);

    void recordBlacklistRemoval();

    void recordBlacklistEvent(String eventType, String ipAddress, Map<String, String> dimensions);

    <T> T timeBlacklistOperation(String operationName, Supplier<T> operation);

    void recordBlacklistPayloadSize(String operationType, int bytes);

    void incrementCounter(String name, String... tags);

    // ✅ New method to record time durations
    void recordTimer(String name, Duration duration, String... tags);
}

