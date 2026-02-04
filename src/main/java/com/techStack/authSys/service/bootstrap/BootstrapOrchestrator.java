package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.config.core.AppConfigProperties;
import com.techStack.authSys.repository.metrics.MetricsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Bootstrap Orchestrator
 *
 * Entry point for Super Admin bootstrap process.
 * Uses Clock for timestamp tracking and coordinates all bootstrap services.
 */
@Slf4j
@Component
@Order(2) // Run after cleanup (Order 1)
@RequiredArgsConstructor
public class BootstrapOrchestrator implements CommandLineRunner {

    /* =========================
       Dependencies
       ========================= */

    private final BootstrapLockService lockService;
    private final BootstrapValidationService validationService;
    private final BootstrapStateService stateService;
    private final TransactionalBootstrapService transactionalService;
    private final MetricsService metricsService;
    private final AppConfigProperties appConfig;
    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    private static final Duration BOOTSTRAP_TIMEOUT = Duration.ofMinutes(10);

    /* =========================
       Startup Execution
       ========================= */

    @Override
    public void run(String... args) {
        Instant startTime = clock.instant();

        log.info("🚀 Initiating Super Admin bootstrap check at {}", startTime);

        // Validate configuration
        if (!validationService.validateBootstrapConfig(appConfig)) {
            log.error("❌ Bootstrap configuration invalid — skipping at {}",
                    clock.instant());
            metricsService.incrementCounter("bootstrap.config.invalid");
            return;
        }

        // Execute bootstrap with lock
        performBootstrapWithLock()
                .timeout(BOOTSTRAP_TIMEOUT)
                .doOnSuccess(v -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.info("✅ Bootstrap completed successfully at {} (duration: {})",
                            endTime, duration);
                    metricsService.incrementCounter("bootstrap.completed");
                    metricsService.recordTimer("bootstrap.total.time", duration);
                })
                .doOnError(e -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.error("💥 Bootstrap failed after {} at {}: {}",
                            duration, endTime, e.getMessage(), e);
                    metricsService.incrementCounter("bootstrap.failure");
                })
                .subscribe(); // Non-blocking startup
    }

    /* =========================
       Bootstrap Execution
       ========================= */

    /**
     * Acquire bootstrap lock and execute transactional creation
     */
    private Mono<Void> performBootstrapWithLock() {
        Instant now = clock.instant();

        return lockService.acquireBootstrapLock()
                .flatMap(lockAcquired -> {
                    if (lockAcquired) {
                        log.info("🔒 Bootstrap lock acquired at {}", now);

                        return executeBootstrapProcess()
                                .doFinally(signal -> {
                                    lockService.releaseBootstrapLock();
                                    log.info("🔓 Bootstrap lock released at {}", clock.instant());
                                });
                    } else {
                        log.info("⏳ Another instance performing bootstrap at {}", now);
                        return stateService.waitForBootstrapCompletion();
                    }
                })
                .onErrorResume(e -> {
                    log.error("❌ Bootstrap coordination failed at {}: {}",
                            clock.instant(), e.getMessage(), e);
                    lockService.releaseBootstrapLock();
                    return Mono.empty();
                });
    }

    /**
     * Execute the transactional bootstrap process
     */
    private Mono<Void> executeBootstrapProcess() {
        Instant now = clock.instant();

        return stateService.isBootstrapCompleted()
                .flatMap(alreadyBootstrapped -> {
                    if (alreadyBootstrapped) {
                        log.info("✅ Bootstrap previously completed — skipping at {}", now);
                        return Mono.empty();
                    }

                    log.info("🔐 Creating Super Admin with transactional guarantees at {}", now);

                    return transactionalService.createSuperAdminTransactionally(
                            appConfig.getSuperAdminEmail(),
                            appConfig.getSuperAdminPhone()
                    );
                });
    }
}
