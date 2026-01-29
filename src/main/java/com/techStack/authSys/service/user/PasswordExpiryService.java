package com.techStack.authSys.service.user;

import com.techStack.authSys.exception.password.PasswordExpiredException;
import com.techStack.authSys.exception.password.PasswordWarningException;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.models.common.ProcessResult;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserPasswordHistory;
import com.techStack.authSys.repository.sucurity.AccountLockService;
import com.techStack.authSys.repository.user.CustomAuthRepository;
import com.techStack.authSys.repository.user.UserPasswordHistoryRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.notification.EmailServiceInstance1;
import com.techStack.authSys.service.security.EncryptionService;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import org.springframework.scheduling.support.CronTrigger;
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

@Service
//@RequiredArgsConstructor
@Slf4j
public class PasswordExpiryService {

    private final UserPasswordHistoryRepository passwordHistoryRepository;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final EncryptionService encryptionService;
    private final Clock clock;  // For testability
    private final AccountLockService lockService;
    private final TaskScheduler taskScheduler;
    private final EmailServiceInstance1 emailServiceInstance1;
    private final DistributionSummary cleanupDurationMetrics;
    private final DistributionSummary entriesRemovedMetrics;
    private final CustomAuthRepository customAuthRepository;

    private final AtomicLong cleanedUsersCount = new AtomicLong();
    private final AtomicLong skippedUsersCount = new AtomicLong();
    private final AtomicLong failedUsersCount = new AtomicLong();
    private final AtomicReference<ScheduledFuture<?>> cleanupFuture = new AtomicReference<>();

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

    public PasswordExpiryService(UserPasswordHistoryRepository passwordHistoryRepository,
                                 FirebaseServiceAuth firebaseServiceAuth,
                                 EncryptionService encryptionService,
                                 Clock clock,
                                 AccountLockService lockService,
                                 TaskScheduler taskScheduler,
                                 EmailServiceInstance1 emailServiceInstance1,
                                 MeterRegistry meterRegistry,
                                 CustomAuthRepository customAuthRepository, List<Integer> notificationDays) {
        this.passwordHistoryRepository = passwordHistoryRepository;
        this.firebaseServiceAuth = firebaseServiceAuth;
        this.encryptionService = encryptionService;
        this.clock = clock;
        this.lockService = lockService;
        this.taskScheduler = taskScheduler;
        this.emailServiceInstance1 = emailServiceInstance1;
        this.cleanupDurationMetrics = DistributionSummary
                .builder("password.cleanup.duration")
                .description("Time taken for password cleanup in seconds")
                .register(meterRegistry);

        this.entriesRemovedMetrics = DistributionSummary
                .builder("password.cleanup.entries.removed")
                .description("Number of password entries removed per user")
                .register(meterRegistry);
        this.customAuthRepository = customAuthRepository;
        this.notificationDays = notificationDays;
    }

    @PostConstruct
    public void init() {
        scheduleDailyExpiryCheck();
        scheduleWeeklyCleanup();
    }

    private void scheduleDailyExpiryCheck() {
        taskScheduler.schedule(
                this::checkAllUsersPasswordExpiry,
                new CronTrigger("0 0 2 * * ?") // Daily at 2 AM
        );
        log.info("Scheduled daily password expiry check at 2 AM");
    }
    private void scheduleWeeklyCleanup() {
        ScheduledFuture<?> existing = cleanupFuture.getAndSet(null);
        if (existing != null && !existing.isCancelled()) {
            existing.cancel(true); // Cancel existing schedule
        }

        ScheduledFuture<?> future = taskScheduler.schedule(
                () -> {
                    Instant start = Instant.now();
                    log.info("Starting weekly password history cleanup");

                    cleanupOldPasswordHistory()
                            .doOnSubscribe(sub -> log.debug("Cleanup process initiated"))
                            .doOnSuccess(v -> {
                                Duration duration = Duration.between(start, Instant.now());
                                log.info("Cleanup completed successfully in {}", duration);
                                cleanupDurationMetrics.record(duration.toMillis());
                            })
                            .doOnError(error -> {
                                Duration duration = Duration.between(start, Instant.now());
                                log.error("Cleanup failed after {}", duration, error);
                                cleanupDurationMetrics.record(duration.toMillis());
                            })
                            .subscribe(null, error -> log.error("Cleanup subscription error", error));
                },
                new CronTrigger("0 0 3 ? * SUN")
        );

        cleanupFuture.set(future);
        log.info("Scheduled weekly password history cleanup on Sundays at 3 AM");
    }
    @PreDestroy
    public void cleanup() {
        ScheduledFuture<?> future = cleanupFuture.get();
        if (future != null && !future.isCancelled()) {
            future.cancel(true);
            log.info("Cancelled weekly password history cleanup");
        }
    }

    public Mono<Void> cleanupOldPasswordHistory() {
        cleanedUsersCount.set(0);
        skippedUsersCount.set(0);
        failedUsersCount.set(0);

        if (maxPasswordHistoryEntries <= 0) {
            log.warn("Skipping cleanup - invalid maxPasswordHistoryEntries: {}", maxPasswordHistoryEntries);
            return Mono.empty();
        }

        int pageSize = 100;
        AtomicReference<String> cursorRef = new AtomicReference<>(null); // Start with no cursor

        return Flux.defer(() -> fetchPageAfterUsername(cursorRef.get(), pageSize))
                .expand(users -> {
                    if (users.isEmpty()) return Mono.empty(); // No more pages
                    String lastUsername = users.get(users.size() - 1).getUsername();
                    cursorRef.set(lastUsername);
                    return fetchPageAfterUsername(lastUsername, pageSize);
                })
                .flatMap(Flux::fromIterable, 5) // Flatten each page
                .flatMap(this::processUser, 10) // Process each user
                .onErrorContinue((e, u) -> log.error("Error cleaning user: {}", u, e))
                .then(Mono.fromRunnable(() -> log.info("Cleanup completed. Cleaned: {}, Skipped: {}, Failed: {}",
                        cleanedUsersCount.get(), skippedUsersCount.get(), failedUsersCount.get())));
    }

    private Mono<List<User>> fetchPageAfterUsername(String cursorUsername, int pageSize) {
        return customAuthRepository.findUsersAfterCursor(cursorUsername, pageSize)
                .collectList();
    }


    private Mono<User> processUser(User user) {
        List<UserPasswordHistory> history = user.getPasswordHistory();
        if (history == null || history.size() <= maxPasswordHistoryEntries) {
            skippedUsersCount.incrementAndGet();
            return Mono.just(user);
        }

        int removedCount = history.size() - maxPasswordHistoryEntries;
        List<UserPasswordHistory> trimmed = history.stream()
                .sorted(Comparator.comparing(UserPasswordHistory::getChangedAt).reversed())
                .limit(maxPasswordHistoryEntries)
                .collect(Collectors.toList());

        user.setPasswordHistory(trimmed);
        return firebaseServiceAuth.save(user)
                .doOnSuccess(updated -> {
                    cleanedUsersCount.incrementAndGet();
                    entriesRemovedMetrics.record(removedCount);
                    log.debug("Removed {} entries from user {}", removedCount, updated.getUsername());
                });
    }

    public void checkAllUsersPasswordExpiry() {
        AtomicLong startTime = new AtomicLong(System.currentTimeMillis());
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
                            log.warn("Failed to process user {}: {}", user.getId(), e.getMessage(), e);
                        })
                        .onErrorResume(e -> Mono.just(ProcessResult.FAILED))
                )
                .sequential()  // ✔️ this is now on ParallelFlux
                .then()
                .then(Mono.defer(() -> {
                    long duration = System.currentTimeMillis() - startTime.get();
                    log.info("""
                                    Password expiry check completed in {} ms
                                    Processed: {}, Warnings: {}, Expired: {}, Failed: {}
                                    """,
                            duration, processedCount.get(), warningCount.get(),
                            expiredCount.get(), failedCount.get());
                    return Mono.empty();
                }));
    }

    private Mono<ProcessResult> processUserExpiry(User user) {
        return checkPasswordExpiry(user.getId(), user.getPassword())
                .thenReturn(ProcessResult.OK)
                .onErrorResume(PasswordWarningException.class, e ->
                        handleWarning(user, e).thenReturn(ProcessResult.WARNING))
                .onErrorResume(PasswordExpiredException.class, e ->
                        handleExpiration(user, e).thenReturn(ProcessResult.EXPIRED))
                .onErrorResume(e -> {
                    log.error("Unexpected error processing user {}", user.getId(), e);
                    return Mono.just(ProcessResult.FAILED);
                });
    }

    private Mono<Void> handleWarning(User user, PasswordWarningException e) {
        int daysRemaining = calculateDaysRemaining(user);

        if (notificationDays.contains(daysRemaining)) {
            return emailServiceInstance1.sendPasswordExpiryWarning(
                    user.getEmail(),
                    daysRemaining,
                    null
            );
        }
        return Mono.empty();
    }
    private Mono<Instant> getExpiryDate(String id) {
        return firebaseServiceAuth.getUserById(id)
                .switchIfEmpty(Mono.error(new UserNotFoundException(id)))
                .flatMap(user -> {
                    try {
                        Instant lastChange = Instant.parse(user.getLastPasswordChangeDate());
                        return Mono.just(lastChange.plus(passwordExpiryDays, ChronoUnit.DAYS));
                    } catch (DateTimeParseException e) {
                        return Mono.error(new IllegalStateException("Invalid password change date format"));
                    } catch (NullPointerException e) {
                        return Mono.error(new IllegalStateException("No password change date recorded"));
                    }
                });
    }
    private Mono<Void> handleExpiration(User user, PasswordExpiredException e) {
        return getExpiryDate(user.getId())
                .zipWith(Mono.just(Instant.now(clock)))
                .flatMap(tuple -> {
                    Instant expiryDate = tuple.getT1();
                    Instant now = tuple.getT2();
                    long daysExpired = Duration.between(expiryDate, now).toDays();

                    return daysExpired >= lockAfterExpiryDays
                            ? lockAndNotify(user, daysExpired)
                            : notifyOnly(user, daysExpired);
                })
                .onErrorResume(this::handleExpirationError)
                //.metrics() // Add metrics for monitoring
                .timeout(Duration.ofSeconds(30));
    }

    private Mono<Void> lockAndNotify(User user, long daysExpired) {
        return lockService.lockAccount(
                        user.getId(),
                        String.format("Password expired for %d days", daysExpired),
                        null
                )
                .then(emailServiceInstance1.sendPasswordExpiredNotification(
                        user.getEmail(),
                        daysExpired,
                        "Your account has been locked due to password expiration"
                ));
    }

    private Mono<Void> notifyOnly(User user, long daysExpired) {
        return emailServiceInstance1.sendPasswordExpiredNotification(
                user.getEmail(),
                daysExpired,
                "Please change your password immediately"
        );
    }

    private Mono<Void> handleExpirationError(Throwable error) {
        if (error instanceof UserNotFoundException) {
            logSecurityEvent("UNKNOWN", "USER_NOT_FOUND", error.getMessage());
        } else {
            log.error("Password expiration handling failed", error);
        }
        return Mono.empty();
    }

    private int calculateDaysRemaining(User user) {
        Instant expiryDate = getExpiryDate(user.getId()).block();
        return (int) Duration.between(Instant.now(clock), expiryDate).toDays();
    }
    /**
     * Checks if the user's password has expired or is close to expiring
     */
    public Mono<Void> checkPasswordExpiry(String userId, String plainPassword) {
        return getLatestPasswordHistory(userId, plainPassword)
                .flatMap(passwordHistory -> validatePasswordExpiry(userId, passwordHistory))
                .doOnError(e -> log.warn("Password expiry check failed for user {}: {}", userId, e.getMessage()));
    }

    private Mono<UserPasswordHistory> getLatestPasswordHistory(String userId, String plainPassword) {
        return passwordHistoryRepository.findFirstByUserIdOrderByCreatedAtDesc(userId)
                .switchIfEmpty(Mono.defer(() -> createInitialPasswordHistory(userId, plainPassword)));
    }

    private Mono<UserPasswordHistory> createInitialPasswordHistory(String userId, String plainPassword) {
        Instant now = Instant.now(clock);
        String encryptedPassword = encryptionService.encrypt(plainPassword);

        UserPasswordHistory history = UserPasswordHistory.builder()
                .userId(userId)
                .password(encryptedPassword)
                .createdAt(now)
                .build();

        return passwordHistoryRepository.save(history)
                .doOnSuccess(h -> log.debug("Created initial password history for user {}", userId));
    }

    private Mono<Void> validatePasswordExpiry(String userId, UserPasswordHistory history) {
        return Mono.fromSupplier(() -> {
            Instant lastChanged = history.getCreatedAt();
            if (lastChanged == null) {
                throw new IllegalStateException("Invalid password history record");
            }

            Instant expiryDate = lastChanged.plus(Duration.ofDays(passwordExpiryDays));
            Instant warningDate = expiryDate.minus(Duration.ofDays(passwordWarningDays));
            Instant now = Instant.now(clock);

            if (now.isAfter(expiryDate)) {
                logSecurityEvent(userId, "PASSWORD_EXPIRED", "Password expired on " + expiryDate);
                throw new PasswordExpiredException("Your password has expired. Please reset it immediately.");
            }

            if (now.isAfter(warningDate)) {
                logSecurityEvent(userId, "PASSWORD_WARNING", "Password will expire on " + expiryDate);
                throw new PasswordWarningException(
                        String.format("Your password will expire in %d days. Please change it soon.",
                                Duration.between(now, expiryDate).toDays()));
            }
            return null;
        });
    }

    private void logSecurityEvent(String userId, String eventType, String details) {
        log.info("Security Event - User: {}, Type: {}, Details: {}",
                userId, eventType, details);
    }

}