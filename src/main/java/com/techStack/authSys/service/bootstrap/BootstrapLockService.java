package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.service.RedisCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;

/**
 * Manages distributed locking for bootstrap operations.
 * Ensures only one instance can perform bootstrap at a time.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapLockService {

    private final RedisCacheService redisCacheService;

    private static final String LOCK_KEY = "bootstrap:lock";
    private static final Duration LOCK_TIMEOUT = Duration.ofMinutes(5);

    /**
     * Attempts to acquire the bootstrap lock.
     *
     * @return true if lock acquired, false otherwise
     */
    public Mono<Boolean> acquireBootstrapLock() {
        String lockValue = generateLockValue();

        return redisCacheService.acquireLock(LOCK_KEY, lockValue, LOCK_TIMEOUT)
                .doOnNext(acquired -> {
                    if (acquired) {
                        log.info("🔒 Bootstrap lock acquired (timeout: {})", LOCK_TIMEOUT);
                    } else {
                        log.info("⏳ Bootstrap lock already held by another instance");
                    }
                })
                .onErrorResume(e -> {
                    log.warn("⚠️ Failed to acquire bootstrap lock: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Releases the bootstrap lock.
     */
    public void releaseBootstrapLock() {
        redisCacheService.releaseLock(LOCK_KEY)
                .doOnSuccess(v -> log.info("🔓 Bootstrap lock released"))
                .doOnError(e -> log.warn("⚠️ Failed to release bootstrap lock: {}", e.getMessage()))
                .onErrorResume(e -> Mono.empty())
                .subscribe(); // Fire and forget
    }

    /**
     * Generates a unique lock value for this instance.
     */
    private String generateLockValue() {
        return String.format("%s-%d",
                Thread.currentThread().getName(),
                Instant.now().toEpochMilli());
    }
}
