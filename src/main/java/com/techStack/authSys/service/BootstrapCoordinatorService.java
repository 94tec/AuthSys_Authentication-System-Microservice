package com.techStack.authSys.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

@Service
@Slf4j
@RequiredArgsConstructor
public class BootstrapCoordinatorService {

    private final RedisCacheService redisCacheService;
    private final BootstrapFlagService bootstrapFlagService;

    private static final String LOCK_KEY = "bootstrap:lock";

    public Mono<Boolean> acquireBootstrapLock() {
        return redisCacheService.acquireLock(LOCK_KEY, Instant.now().toString(), Duration.ofMinutes(5))
                .doOnNext(acquired -> log.info(acquired
                        ? "🔒 Bootstrap lock acquired"
                        : "⏳ Bootstrap lock unavailable"))
                .onErrorResume(e -> {
                    log.warn("Failed to acquire bootstrap lock: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    public void releaseBootstrapLock() {
        redisCacheService.releaseLock(LOCK_KEY)
                .doOnSuccess(v -> log.info("🔓 Bootstrap lock released"))
                .onErrorResume(e -> {
                    log.warn("⚠️ Failed to release bootstrap lock: {}", e.getMessage());
                    return Mono.empty();
                })
                .subscribe();
    }

    public Mono<Void> waitForBootstrapCompletion() {
        return bootstrapFlagService.isBootstrapCompleted()
                .filter(Boolean::booleanValue)
                .repeatWhenEmpty(flux -> flux.delayElements(Duration.ofSeconds(2)))
                .timeout(Duration.ofMinutes(5)) // avoid indefinite wait
                .then();
    }
}

