package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.config.core.AppConfigProperties;
import com.techStack.authSys.dto.response.BootstrapResult;
import com.techStack.authSys.exception.bootstrap.BootstrapInitializationException;
import com.techStack.authSys.repository.metrics.MetricsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Bootstrap Orchestrator

 */
@Slf4j
@Component
@Order(2)
@RequiredArgsConstructor
public class BootstrapOrchestrator implements CommandLineRunner {

    private final BootstrapLockService lockService;
    private final BootstrapValidationService validationService;
    private final BootstrapStateService stateService;
    private final TransactionalBootstrapService transactionalService;
    private final MetricsService metricsService;
    private final AppConfigProperties appConfig;
    private final Clock clock;

    private static final Duration BOOTSTRAP_TIMEOUT = Duration.ofMinutes(10);
    private static final int MAX_RETRIES = 3;
    private static final Duration RETRY_DELAY = Duration.ofSeconds(5);

    /* =========================
       CommandLineRunner Entry
       ========================= */

    @Override
    public void run(String... args) {
        Instant startTime = clock.instant();
        log.info("🚀 Initiating Super Admin bootstrap check at {}", startTime);

        // Validate configuration FIRST — fail immediately on bad config
        if (!validationService.validateBootstrapConfig(appConfig)) {
            String msg = "Bootstrap configuration validation failed — check email and phone settings";
            log.error("❌ {}", msg);
            metricsService.incrementCounter("bootstrap.config.invalid");
            throw new BootstrapInitializationException(msg, "CONFIG_VALIDATION");
        }

        try {
            performBootstrapWithLock()
                    .timeout(BOOTSTRAP_TIMEOUT)
                    .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                            .maxBackoff(Duration.ofSeconds(30))
                            .filter(this::isRetryableError)
                            .doBeforeRetry(signal -> {
                                log.warn("⚠️ Retrying bootstrap (attempt {}/{}): {}",
                                        signal.totalRetries() + 1, MAX_RETRIES,
                                        signal.failure().getMessage());
                                metricsService.incrementCounter("bootstrap.retry.attempt");
                            })
                            .onRetryExhaustedThrow((spec, signal) -> {
                                String msg = String.format("Bootstrap failed after %d retries: %s",
                                        MAX_RETRIES, signal.failure().getMessage());
                                log.error("💥 {}", msg);
                                return new BootstrapInitializationException(
                                        msg, "RETRY_EXHAUSTED", signal.failure(), false);
                            }))
                    .doOnSuccess(result -> {
                        Instant endTime = clock.instant();
                        Duration duration = Duration.between(startTime, endTime);

                        if (result.created()) {
                            log.info("✅ Super Admin CREATED at {} (duration: {}) — Email sent: {}",
                                    endTime, duration, result.emailSent());
                            metricsService.incrementCounter("bootstrap.super_admin.created");
                        } else if (result.alreadyExists()) {
                            log.info("✅ Super Admin already EXISTS — verified at {} (duration: {})",
                                    endTime, duration);
                            metricsService.incrementCounter("bootstrap.super_admin.already_exists");
                        }

                        metricsService.incrementCounter("bootstrap.completed");
                        metricsService.recordTimer("bootstrap.total.time", duration);
                    })
                    /*
                     * ✅ FIXED: was .doOnError(e -> { throw new ... })
                     *
                     * Throwing inside doOnError() is a Project Reactor violation.
                     * The thrown exception bypasses the reactive error channel and
                     * becomes an UndeliverableException — it is NOT caught by the
                     * outer try/catch and crashes the thread silently.
                     *
                     * onErrorMap() correctly transforms the error within the pipeline
                     * so it surfaces through .block() as a normal exception.
                     */
                    .onErrorMap(e -> {
                        if (e instanceof BootstrapInitializationException) return e;
                        return new BootstrapInitializationException(
                                "Bootstrap failed: " + e.getMessage(),
                                "EXECUTION_FAILED", e, false);
                    })
                    .block(); // 🔥 Block and fail startup on error — intentional

        } catch (Exception e) {
            if (e instanceof BootstrapInitializationException) throw e;
            String msg = "Bootstrap initialization failed: " + e.getMessage();
            log.error("💥 FATAL: {}", msg, e);
            throw new BootstrapInitializationException(msg, "UNKNOWN", e, false);
        }
    }

    /* =========================
       Lock Coordination
       ========================= */

    /**
     * ✅ FIXED: Returns Mono<BootstrapResult> (was Mono<Void>).
     * The lock-wait else-branch now correctly returns a BootstrapResult.
     */
    private Mono<BootstrapResult> performBootstrapWithLock() {
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
                        log.info("⏳ Another instance is bootstrapping at {}", now);
                        // Wait for the other instance to finish, then report existing
                        return stateService.waitForBootstrapCompletion()
                                .then(Mono.just(BootstrapResult.alreadyExists(null)));
                    }
                })
                .onErrorResume(e -> {
                    log.error("❌ Bootstrap coordination failed: {}", e.getMessage(), e);
                    lockService.releaseBootstrapLock();
                    return Mono.error(new BootstrapInitializationException(
                            "Bootstrap coordination failed: " + e.getMessage(),
                            "LOCK_COORDINATION", e, isRetryableError(e)));
                });
    }

    /* =========================
       Bootstrap Process
       ========================= */

    private Mono<BootstrapResult> executeBootstrapProcess() {
        Instant now = clock.instant();

        return stateService.isBootstrapCompleted()
                .flatMap(alreadyDone -> {
                    if (alreadyDone) {
                        log.info("✅ Bootstrap previously completed — skipping at {}", now);
                        return Mono.just(BootstrapResult.alreadyExists(null));
                    }

                    log.info("🔐 Creating Super Admin at {}", now);
                    return transactionalService.createSuperAdminTransactionally(
                            appConfig.getSuperAdminEmail(),
                            appConfig.getSuperAdminPhone());
                })
                .onErrorResume(e -> Mono.error(new BootstrapInitializationException(
                        "Bootstrap process failed: " + e.getMessage(),
                        "BOOTSTRAP_EXECUTION", e, isRetryableError(e))));
    }

    /* =========================
       Retry Classification
       ========================= */

    private boolean isRetryableError(Throwable error) {
        if (error instanceof BootstrapInitializationException) {
            return ((BootstrapInitializationException) error).isRetryable();
        }
        return com.techStack.authSys.util.validation.HelperUtils.isRetryableError(error);
    }
}