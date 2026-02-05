package com.techStack.authSys.service.user;

import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.password.PasswordExpiredException;
import com.techStack.authSys.exception.password.PasswordWarningException;
import com.techStack.authSys.models.common.ProcessResult;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserPasswordHistory;
import com.techStack.authSys.repository.user.CustomAuthRepository;
import com.techStack.authSys.repository.user.UserPasswordHistoryRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.notification.EmailServiceInstance;
import com.techStack.authSys.service.security.AccountLockServiceImpl;
import com.techStack.authSys.service.security.EncryptionService;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Password Expiry Service
 *
 * Manages password expiration, warnings, and history cleanup.
 * Uses Clock for all timestamp operations.
 */
@Service
@Slf4j
public class PasswordExpiryService {

    /* =========================
       Configuration
       ========================= */

    @Value("${security.password.expiry.days:90}")
    private int passwordExpiryDays;

    @Value("${security.password.warning.days:7}")
    private int passwordWarningDays;

    @Value("${security.password.history.max.entries:5}")
    private int maxPasswordHistoryEntries;

    @Value("${security.password.history.check:true}")
    private boolean checkPasswordHistory;

    @Value("${password.expiry.notification.days:7,3,1}")
    private List<Integer> notificationDays;

    @Value("${password.expiry.lock.after.days:3}")
    private int lockAfterExpiryDays;

    /* =========================
       Dependencies
       ========================= */

    private final UserPasswordHistoryRepository passwordHistoryRepository;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final EncryptionService encryptionService;
    private final Clock clock;
    private final AccountLockServiceImpl lockService;
    private final TaskScheduler taskScheduler;
    private final EmailServiceInstance emailServiceInstance1;
    private final CustomAuthRepository customAuthRepository;

    /* =========================
       Metrics
       ========================= */

    private final DistributionSummary cleanupDurationMetrics;
    private final DistributionSummary entriesRemovedMetrics;

    /* =========================
       State Management
       ========================= */

    private final AtomicLong cleanedUsersCount = new AtomicLong();
    private final AtomicLong skippedUsersCount = new AtomicLong();
    private final AtomicLong failedUsersCount = new AtomicLong();
    private final AtomicReference<ScheduledFuture<?>> cleanupFuture = new AtomicReference<>();

    /* =========================
       Constructor
       ========================= */

    public PasswordExpiryService(
            UserPasswordHistoryRepository passwordHistoryRepository,
            FirebaseServiceAuth firebaseServiceAuth,
            EncryptionService encryptionService,
            Clock clock,
            AccountLockServiceImpl lockService,
            TaskScheduler taskScheduler,
            EmailServiceInstance emailServiceInstance1,
            MeterRegistry meterRegistry,
            CustomAuthRepository customAuthRepository
    ) {
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.encryptionService = encryptionService;
        this.clock = clock;
        this.lockService = lockService;
        this.taskScheduler = taskScheduler;
        this.emailServiceInstance1 = emailServiceInstance1;
        this.customAuthRepository = customAuthRepository;

        this.cleanupDurationMetrics = DistributionSummary
                .builder("password.cleanup.duration")
                .description("Time taken for password cleanup in seconds")
                .register(meterRegistry);

        this.entriesRemovedMetrics = DistributionSummary
                .builder("password.cleanup.entries.removed")
                .description("Number of password entries removed per user")
                .register(meterRegistry);
    }

    /* =========================
       Initialization
       ========================= */

    @PostConstruct
    public void init() {
        Instant now = clock.instant();
        scheduleDailyExpiryCheck();
        scheduleWeeklyCleanup();
        log.info("PasswordExpiryService initialized at {}", now);
    }

    @PreDestroy
    public void cleanup() {
        Instant now = clock.instant();
        ScheduledFuture<?> future = cleanupFuture.get();

        if (future != null && !future.isCancelled()) {
            future.cancel(true);
            log.info("Cancelled weekly password history cleanup at {}", now);
        }
    }

    /* =========================
       Scheduled Tasks
       ========================= */

    /**
     * Schedule daily expiry check at 2 AM
     */
    private void scheduleDailyExpiryCheck() {
        taskScheduler.schedule(
                this::checkAllUsersPasswordExpiry,
                new CronTrigger("0 0 2 * * ?")
        );
        log.info("Scheduled daily password expiry check at 2 AM");
    }

    /**
     * Schedule weekly cleanup on Sundays at 3 AM
     */
    private void scheduleWeeklyCleanup() {
        ScheduledFuture<?> existing = cleanupFuture.getAndSet(null);
        if (existing != null && !existing.isCancelled()) {
            existing.cancel(true);
        }

        ScheduledFuture<?> future = taskScheduler.schedule(
                () -> {
                    Instant start = clock.instant();
                    log.info("Starting weekly password history cleanup at {}", start);

                    cleanupOldPasswordHistory()
                            .doOnSubscribe(sub -> log.debug("Cleanup process initiated at {}", start))
                            .doOnSuccess(v -> {
                                Instant end = clock.instant();
                                Duration duration = Duration.between(start, end);
                                log.info("Cleanup completed successfully at {} (duration: {})", end, duration);
                                cleanupDurationMetrics.record(duration.toMillis());
                            })
                            .doOnError(error -> {
                                Instant end = clock.instant();
                                Duration duration = Duration.between(start, end);
                                log.error("Cleanup failed at {} (duration: {})", end, duration, error);
                                cleanupDurationMetrics.record(duration.toMillis());
                            })
                            .subscribe(
                                    null,
                                    error -> log.error("Cleanup subscription error", error)
                            );
                },
                new CronTrigger("0 0 3 ? * SUN")
        );

        cleanupFuture.set(future);
        log.info("Scheduled weekly password history cleanup on Sundays at 3 AM");
    }

    /* =========================
       Password History Cleanup
       ========================= */

    /**
     * Cleanup old password history entries
     */
    public Mono<Void> cleanupOldPasswordHistory() {
        Instant start = clock.instant();

        cleanedUsersCount.set(0);
        skippedUsersCount.set(0);
        failedUsersCount.set(0);

        if (maxPasswordHistoryEntries <= 0) {
            log.warn("Skipping cleanup at {} - invalid maxPasswordHistoryEntries: {}",
                    start, maxPasswordHistoryEntries);
            return Mono.empty();
        }

        int pageSize = 100;
        AtomicReference<String> cursorRef = new AtomicReference<>(null);

        return Flux.defer(() -> fetchPageAfterUsername(cursorRef.get(), pageSize))
                .expand(users -> {
                    if (users.isEmpty()) return Mono.empty();
                    String lastUsername = users.get(users.size() - 1).getUsername();
                    cursorRef.set(lastUsername);
                    return fetchPageAfterUsername(lastUsername, pageSize);
                })
                .flatMap(Flux::fromIterable, 5)
                .flatMap(this::processUser, 10)
                .onErrorContinue((e, u) -> log.error("Error cleaning user at {}: {}",
                        clock.instant(), u, e))
                .then(Mono.fromRunnable(() -> {
                    Instant end = clock.instant();
                    Duration duration = Duration.between(start, end);

                    log.info("""
                            Cleanup completed at {} (duration: {})
                            Cleaned: {}, Skipped: {}, Failed: {}
                            """,
                            end, duration,
                            cleanedUsersCount.get(),
                            skippedUsersCount.get(),
                            failedUsersCount.get());
                }));
    }

    /**
     * Fetch page of users after cursor
     */
    private Mono<List<User>> fetchPageAfterUsername(String cursorUsername, int pageSize) {
        return customAuthRepository.findUsersAfterCursor(cursorUsername, pageSize)
                .collectList();
    }

    /**
     * Process individual user
     */
    private Mono<User> processUser(User user) {
        List<UserPasswordHistory> history = user.getPasswordHistoryEntries();

        if (history == null || history.size() <= maxPasswordHistoryEntries) {
            skippedUsersCount.incrementAndGet();
            return Mono.just(user);
        }

        int removedCount = history.size() - maxPasswordHistoryEntries;
        List<UserPasswordHistory> trimmed = history.stream()
                .sorted(Comparator.comparing(UserPasswordHistory::getCreatedAt).reversed())
                .limit(maxPasswordHistoryEntries)
                .collect(Collectors.toList());

        user.setPasswordHistoryEntries(trimmed);

        return firebaseServiceAuth.save(user)
                .doOnSuccess(updated -> {
                    cleanedUsersCount.incrementAndGet();
                    entriesRemovedMetrics.record(removedCount);
                    log.debug("Removed {} entries from user {} at {}",
                            removedCount, updated.getUsername(), clock.instant());
                })
                .doOnError(e -> {
                    failedUsersCount.incrementAndGet();
                    log.error("Failed to process user {} at {}: {}",
                            user.getUsername(), clock.instant(), e.getMessage());
                });
    }

    /* =========================
       Expiry Checking
       ========================= */

    /**
     * Check all users' password expiry
     */
    public void checkAllUsersPasswordExpiry() {
        Instant startTime = clock.instant();
        AtomicInteger processedCount = new AtomicInteger();
        AtomicInteger warningCount = new AtomicInteger();
        AtomicInteger expiredCount = new AtomicInteger();
        AtomicInteger failedCount = new AtomicInteger();

        firebaseServiceAuth.findAllUsers()
                .name("passwordExpiryCheck")
                .limitRate(100)
                .parallel(4)
                .runOn(Schedulers.boundedElastic())
                .flatMap(user -> processUserExpiry(user)
                        .doOnNext(result -> {
                            processedCount.incrementAndGet();
                            if (result == ProcessResult.WARNING) {
                                warningCount.incrementAndGet();
                            } else if (result == ProcessResult.EXPIRED) {
                                expiredCount.incrementAndGet();
                            }
                        })
                        .doOnError(e -> {
                            failedCount.incrementAndGet();
                            log.warn("Failed to process user {} at {}: {}",
                                    user.getId(), clock.instant(), e.getMessage(), e);
                        })
                        .onErrorResume(e -> Mono.just(ProcessResult.FAILED))
                )
                .sequential()
                .then()
                .then(Mono.defer(() -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.info("""
                            Password expiry check completed at {} (duration: {})
                            Processed: {}, Warnings: {}, Expired: {}, Failed: {}
                            """,
                            endTime, duration,
                            processedCount.get(), warningCount.get(),
                            expiredCount.get(), failedCount.get());
                    return Mono.empty();
                }))
                .subscribe();
    }

    /**
     * Process individual user expiry
     */
    private Mono<ProcessResult> processUserExpiry(User user) {
        return checkPasswordExpiry(user.getId(), user.getPassword())
                .thenReturn(ProcessResult.OK)
                .onErrorResume(PasswordWarningException.class, e ->
                        handleWarning(user, e).thenReturn(ProcessResult.WARNING))
                .onErrorResume(PasswordExpiredException.class, e ->
                        handleExpiration(user, e).thenReturn(ProcessResult.EXPIRED))
                .onErrorResume(e -> {
                    log.error("Unexpected error processing user {} at {}",
                            user.getId(), clock.instant(), e);
                    return Mono.just(ProcessResult.FAILED);
                });
    }

    /**
     * Handle password warning
     */
    private Mono<Void> handleWarning(User user, PasswordWarningException e) {
        int daysRemaining = calculateDaysRemaining(user);

        if (notificationDays.contains(daysRemaining)) {
            log.info("Sending password expiry warning to {} ({} days remaining) at {}",
                    user.getEmail(), daysRemaining, clock.instant());

            return emailServiceInstance1.sendPasswordExpiryWarning(
                    user.getEmail(),
                    daysRemaining,
                    null
            );
        }

        return Mono.empty();
    }

    /**
     * Handle password expiration
     */
    private Mono<Void> handleExpiration(User user, PasswordExpiredException e) {
        Instant now = clock.instant();

        return getExpiryDate(user.getId())
                .flatMap(expiryDate -> {
                    long daysExpired = Duration.between(expiryDate, now).toDays();

                    log.warn("Password expired for user {} ({} days ago) at {}",
                            user.getEmail(), daysExpired, now);

                    return daysExpired >= lockAfterExpiryDays
                            ? lockAndNotify(user, daysExpired)
                            : notifyOnly(user, daysExpired);
                })
                .onErrorResume(this::handleExpirationError)
                .timeout(Duration.ofSeconds(30));
    }

    /**
     * Lock account and notify
     */
    private Mono<Void> lockAndNotify(User user, long daysExpired) {
        Instant now = clock.instant();

        return lockService.lockAccount(
                        user.getId(),
                        String.format("Password expired for %d days", daysExpired),
                        Duration.ofDays(lockAfterExpiryDays)
                )
                .doOnSuccess(v -> log.info("Locked account {} due to password expiry at {}",
                        user.getEmail(), now))
                .then(emailServiceInstance1.sendPasswordExpiredNotification(
                        user.getEmail(),
                        daysExpired,
                        "Your account has been locked due to password expiration"
                ));
    }

    /**
     * Notify without locking
     */
    private Mono<Void> notifyOnly(User user, long daysExpired) {
        return emailServiceInstance1.sendPasswordExpiredNotification(
                user.getEmail(),
                daysExpired,
                "Please change your password immediately"
        );
    }

    /**
     * Handle expiration error
     */
    private Mono<Void> handleExpirationError(Throwable error) {
        Instant now = clock.instant();

        if (error instanceof UserNotFoundException) {
            logSecurityEvent("UNKNOWN", "USER_NOT_FOUND", error.getMessage(), now);
        } else {
            log.error("Password expiration handling failed at {}", now, error);
        }

        return Mono.empty();
    }

    /* =========================
       Password Validation
       ========================= */

    /**
     * Check password expiry for user
     */
    public Mono<Void> checkPasswordExpiry(String userId, String plainPassword) {
        Instant now = clock.instant();

        return getLatestPasswordHistory(userId, plainPassword)
                .flatMap(passwordHistory -> validatePasswordExpiry(userId, passwordHistory, now))
                .doOnError(e -> log.warn("Password expiry check failed for user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /**
     * Get latest password history
     */
    private Mono<UserPasswordHistory> getLatestPasswordHistory(String userId, String plainPassword) {
        return passwordHistoryRepository.findFirstByUserIdOrderByCreatedAtDesc(userId)
                .switchIfEmpty(Mono.defer(() -> createInitialPasswordHistory(userId, plainPassword)));
    }

    /**
     * Create initial password history
     */
    private Mono<UserPasswordHistory> createInitialPasswordHistory(String userId, String plainPassword) {
        Instant now = clock.instant();
        String encryptedPassword = encryptionService.encrypt(plainPassword);

        UserPasswordHistory history = UserPasswordHistory.builder()
                .userId(userId)
                .passwordHash(encryptedPassword)
                .createdAt(now)
                .build();

        return passwordHistoryRepository.save(history)
                .doOnSuccess(h -> log.debug("Created initial password history for user {} at {}",
                        userId, now));
    }

    /**
     * Validate password expiry
     */
    private Mono<Void> validatePasswordExpiry(
            String userId,
            UserPasswordHistory history,
            Instant now
    ) {
        return Mono.fromSupplier(() -> {
            Instant lastChanged = history.getCreatedAt();
            if (lastChanged == null) {
                throw new IllegalStateException("Invalid password history record");
            }

            Instant expiryDate = lastChanged.plus(Duration.ofDays(passwordExpiryDays));
            Instant warningDate = expiryDate.minus(Duration.ofDays(passwordWarningDays));

            if (now.isAfter(expiryDate)) {
                logSecurityEvent(userId, "PASSWORD_EXPIRED",
                        "Password expired on " + expiryDate, now);
                throw new PasswordExpiredException(
                        "Your password has expired. Please reset it immediately.");
            }

            if (now.isAfter(warningDate)) {
                long daysRemaining = Duration.between(now, expiryDate).toDays();
                logSecurityEvent(userId, "PASSWORD_WARNING",
                        "Password will expire on " + expiryDate, now);
                throw new PasswordWarningException(
                        String.format("Your password will expire in %d days. Please change it soon.",
                                daysRemaining));
            }

            return null;
        });
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Get expiry date for user
     */
    private Mono<Instant> getExpiryDate(String id) {
        return firebaseServiceAuth.getUserById(id)
                .switchIfEmpty(Mono.error(new UserNotFoundException(id)))
                .flatMap(user -> {
                    try {
                        Instant lastChange = user.getPasswordLastChanged();
                        return Mono.just(lastChange.plus(passwordExpiryDays, ChronoUnit.DAYS));
                    } catch (DateTimeParseException e) {
                        return Mono.error(new IllegalStateException(
                                "Invalid password change date format"));
                    } catch (NullPointerException e) {
                        return Mono.error(new IllegalStateException(
                                "No password change date recorded"));
                    }
                });
    }

    /**
     * Calculate days remaining until expiry
     */
    private int calculateDaysRemaining(User user) {
        Instant now = clock.instant();
        Instant expiryDate = getExpiryDate(user.getId()).block();
        return (int) Duration.between(now, expiryDate).toDays();
    }

    /**
     * Log security event with timestamp
     */
    private void logSecurityEvent(String userId, String eventType, String details, Instant timestamp) {
        log.info("Security Event at {} - User: {}, Type: {}, Details: {}",
                timestamp, userId, eventType, details);
    }
}