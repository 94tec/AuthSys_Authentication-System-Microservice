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

    @Override
    public void run(String... args) {
        Instant startTime = clock.instant();

        log.info("🚀 Initiating Super Admin bootstrap check at {}", startTime);

        // Validate configuration FIRST - fail immediately if invalid
        if (!validationService.validateBootstrapConfig(appConfig)) {
            String errorMsg = "Bootstrap configuration validation failed - check email and phone settings";
            log.error("❌ {}", errorMsg);
            metricsService.incrementCounter("bootstrap.config.invalid");
            throw new BootstrapInitializationException(errorMsg, "CONFIG_VALIDATION");
        }

        // Execute bootstrap with retry and fail-loud semantics
        try {
            performBootstrapWithLock()
                    .timeout(BOOTSTRAP_TIMEOUT)
                    .retryWhen(Retry.backoff(MAX_RETRIES, RETRY_DELAY)
                            .maxBackoff(Duration.ofSeconds(30))
                            .filter(this::isRetryableError)
                            .doBeforeRetry(signal -> {
                                log.warn("⚠️ Retrying bootstrap (attempt {}/{}): {}",
                                        signal.totalRetries() + 1,
                                        MAX_RETRIES,
                                        signal.failure().getMessage());
                                metricsService.incrementCounter("bootstrap.retry.attempt");
                            })
                            .onRetryExhaustedThrow((retryBackoffSpec, retrySignal) -> {
                                Throwable lastError = retrySignal.failure();
                                String msg = String.format("Bootstrap failed after %d retries: %s",
                                        MAX_RETRIES, lastError.getMessage());
                                log.error("💥 {}", msg);
                                return new BootstrapInitializationException(
                                        msg,
                                        "RETRY_EXHAUSTED",
                                        lastError,
                                        false
                                );
                            }))
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
                        log.error("💥 Bootstrap FAILED after {} at {}: {}",
                                duration, endTime, e.getMessage(), e);
                        metricsService.incrementCounter("bootstrap.failure");
                    })
                    .block(); // 🔥 CRITICAL: Block and fail startup if error occurs

        } catch (Exception e) {
            // Re-throw as BootstrapInitializationException if not already
            if (e instanceof BootstrapInitializationException) {
                throw e;
            }
            String msg = "Bootstrap initialization failed: " + e.getMessage();
            log.error("💥 FATAL: {}", msg, e);
            throw new BootstrapInitializationException(msg, "UNKNOWN", e, false);
        }
    }

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

                    // Convert to BootstrapInitializationException
                    return Mono.error(new BootstrapInitializationException(
                            "Bootstrap coordination failed: " + e.getMessage(),
                            "LOCK_COORDINATION",
                            e,
                            isRetryableError(e)
                    ));
                });
    }

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
                            )
                            .doOnSuccess(result -> {
                                log.info("✅ Bootstrap result: created={} exists={} emailSent={}",
                                        result.created(),
                                        result.alreadyExists(),
                                        result.emailSent());
                            })
                            .then(); // ✅ Convert Mono<BootstrapResult> to Mono<Void>
                })
                .onErrorResume(e -> {
                    // Convert any error to BootstrapInitializationException
                    String msg = "Bootstrap process failed: " + e.getMessage();
                    return Mono.error(new BootstrapInitializationException(
                            msg,
                            "BOOTSTRAP_EXECUTION",
                            e,
                            isRetryableError(e)
                    ));
                });
    }

    /**
     * Determine if an error is retryable (transient Firebase/Firestore issues).
     */
    private boolean isRetryableError(Throwable error) {
        if (error instanceof BootstrapInitializationException) {
            return ((BootstrapInitializationException) error).isRetryable();
        }

        // Use your existing HelperUtils method
        return com.techStack.authSys.util.validation.HelperUtils.isRetryableError(error);
    }
}