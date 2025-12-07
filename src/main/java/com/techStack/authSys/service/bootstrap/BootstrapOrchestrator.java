package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.config.AppConfigProperties;
import com.techStack.authSys.repository.MetricsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Orchestrates the Super Admin bootstrap process at application startup.
 * Ensures thread-safe, distributed bootstrap execution with proper error handling.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class BootstrapOrchestrator implements CommandLineRunner {

    private final BootstrapLockService lockService;
    private final BootstrapValidationService validationService;
    private final BootstrapStateService stateService;
    private final SuperAdminCreationService superAdminCreationService;
    private final MetricsService metricsService;
    private final AppConfigProperties appConfig;

    private static final Duration BOOTSTRAP_TIMEOUT = Duration.ofMinutes(10);

    @Override
    public void run(String... args) {
        log.info("🚀 Initiating Super Admin bootstrap check...");

        if (!validationService.validateBootstrapConfig(appConfig)) {
            log.error("❌ Bootstrap configuration invalid — skipping startup bootstrap.");
            metricsService.incrementCounter("bootstrap.config.invalid");
            return;
        }

        performBootstrapWithLock()
                .timeout(BOOTSTRAP_TIMEOUT)
                .doOnSuccess(v -> {
                    log.info("✅ Bootstrap process completed successfully");
                    metricsService.incrementCounter("bootstrap.completed");
                })
                .doOnError(e -> {
                    log.error("💥 Bootstrap process failed: {}", e.getMessage(), e);
                    metricsService.incrementCounter("bootstrap.failure");
                })
                .subscribe(); // Fire and forget - don't block startup
    }

    /**
     * Attempts to acquire bootstrap lock and execute bootstrap.
     * If lock is unavailable, waits for another instance to complete.
     */
    private Mono<Void> performBootstrapWithLock() {
        return lockService.acquireBootstrapLock()
                .flatMap(lockAcquired -> {
                    if (lockAcquired) {
                        return executeBootstrapProcess()
                                .doFinally(signal -> lockService.releaseBootstrapLock());
                    } else {
                        log.info("⏳ Another instance is performing bootstrap. Waiting for completion...");
                        return stateService.waitForBootstrapCompletion();
                    }
                })
                .onErrorResume(e -> {
                    log.error("❌ Bootstrap coordination failed: {}", e.getMessage(), e);
                    lockService.releaseBootstrapLock(); // Ensure lock is released
                    return Mono.empty();
                });
    }

    /**
     * Executes the actual bootstrap process after acquiring lock.
     */
    private Mono<Void> executeBootstrapProcess() {
        return stateService.isBootstrapCompleted()
                .flatMap(alreadyBootstrapped -> {
                    if (alreadyBootstrapped) {
                        log.info("✅ Bootstrap previously completed — skipping.");
                        return Mono.empty();
                    }

                    log.info("🔐 Creating Super Admin account...");
                    return superAdminCreationService.createSuperAdminIfAbsent(
                            appConfig.getSuperAdminEmail(),
                            appConfig.getSuperAdminPhone()
                    );
                });
    }
}
