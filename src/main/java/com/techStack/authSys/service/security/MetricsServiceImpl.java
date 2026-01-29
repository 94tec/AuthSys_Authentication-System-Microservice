package com.techStack.authSys.service.security;

import com.techStack.authSys.repository.metrics.MetricsService;
import io.micrometer.core.instrument.*;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Service
@ConditionalOnProperty(name = "metrics.enabled", havingValue = "true", matchIfMissing = true)
public class MetricsServiceImpl implements MetricsService {

    private static final Logger log = LoggerFactory.getLogger(MetricsServiceImpl.class);
    private final MeterRegistry meterRegistry;
    private final Counter.Builder blacklistEventCounter;
    private final Timer.Builder blacklistOperationTimer;
    private final DistributionSummary blacklistPayloadSize;

    @Autowired
    public MetricsServiceImpl(MeterRegistry meterRegistry,
                              @Value("${app.metrics.prefix:security}") String metricsPrefix) {
        this.meterRegistry = meterRegistry;

        // Initialize metrics builders
        this.blacklistEventCounter = Counter.builder(metricsPrefix + ".blacklist.events")
                .description("Count of blacklist-related events")
                .tags("service", "blacklist-service");

        this.blacklistOperationTimer = Timer.builder(metricsPrefix + ".blacklist.operations")
                .description("Timing of blacklist operations")
                .tags("service", "blacklist-service");

        this.blacklistPayloadSize = DistributionSummary.builder(metricsPrefix + ".blacklist.payload.size")
                .baseUnit("bytes")
                .description("Size of blacklist operation payloads")
                .register(meterRegistry);
    }

    @Override
    public void recordBlacklistEvent(String eventType, String ipAddress) {
        recordBlacklistEvent(eventType, ipAddress, Collections.emptyMap());
    }

    @Override
    public void recordBlacklistRemoval() {

    }

    @Override
    public void recordBlacklistEvent(String eventType, String ipAddress, Map<String, String> dimensions) {
        try {
            // Create tags with common dimensions
            List<Tag> tagList = new ArrayList<>();
            tagList.add(Tag.of("event_type", eventType));
            tagList.add(Tag.of("ip_prefix", getIpPrefix(ipAddress))); // Avoid full IP in metrics
            tagList.add(Tag.of("env", System.getenv().getOrDefault("ENV", "unknown")));

            // Add custom dimensions
            dimensions.forEach((key, value) -> tagList.add(Tag.of(key, value)));

            // Convert list to Tags
            Tags tags = Tags.of(tagList.toArray(new Tag[0]));

            // Record the event
            blacklistEventCounter
                    .tags(tags)
                    .register(meterRegistry)
                    .increment();

            log.debug("Recorded blacklist event: {} for IP prefix {}", eventType, getIpPrefix(ipAddress));
        } catch (Exception e) {
            log.error("Failed to record metrics for event {}: {}", eventType, e.getMessage(), e);
        }
    }


    @Override
    public <T> T timeBlacklistOperation(String operationName, Supplier<T> operation) {
        return blacklistOperationTimer
                .tags("operation", operationName)
                .register(meterRegistry)
                .record(operation);
    }

    @Override
    public void recordBlacklistPayloadSize(String operationType, int bytes) {
        try {
            blacklistPayloadSize.record(bytes);
            log.trace("Recorded payload size {} bytes for {}", bytes, operationType);
        } catch (Exception e) {
            log.error("Failed to record payload size: {}", e.getMessage(), e);
        }
    }

    @Override
    public void incrementCounter(String name, String... tags) {
        if (tags.length % 2 != 0) {
            throw new IllegalArgumentException("Tags must be key-value pairs");
        }
        Counter.builder(name)
                .tags(tags)
                .register(meterRegistry)
                .increment();
    }
    // ✅ New method to record time durations
    @Override
    public void recordTimer(String name, Duration duration, String... tags) {
        if (tags.length % 2 != 0) {
            throw new IllegalArgumentException("Tags must be key-value pairs");
        }
        Timer.builder(name)
                .tags(tags)
                .register(meterRegistry)
                .record(duration);
    }

    private String getIpPrefix(String ipAddress) {
        if (ipAddress == null) return "null";
        int lastDot = ipAddress.lastIndexOf('.');
        return lastDot > 0 ? ipAddress.substring(0, lastDot) + ".x" : ipAddress;
    }

    @PreDestroy
    public void shutdown() {
        log.info("Flushing metrics before shutdown...");
        try {
            meterRegistry.close();
            log.info("Metrics successfully flushed");
        } catch (Exception e) {
            log.error("Error flushing metrics: {}", e.getMessage(), e);
        }
    }
}
