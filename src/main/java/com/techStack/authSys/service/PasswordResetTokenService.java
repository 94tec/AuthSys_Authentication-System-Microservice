package com.techStack.authSys.service;

import com.techStack.authSys.exception.RedisOperationException;
import com.techStack.authSys.exception.TokenNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.RedisConnectionFailureException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.function.Supplier;


@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetTokenService {
    private static final String RESET_PREFIX = "pwd_reset:";
    private static final Duration TTL = Duration.ofHours(1);
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final Duration RETRY_DELAY = Duration.ofMillis(500);

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final MeterRegistry meterRegistry;

    public Mono<String> saveResetToken(String email, String token) {
        if (!StringUtils.hasText(email) || !StringUtils.hasText(token)) {
            log.warn("Attempt to save token with empty email or token");
            meterRegistry.counter("password.reset.token.save.invalid_input").increment();
            return Mono.error(new IllegalArgumentException("Email and token must not be empty"));
        }

        String redisKey = RESET_PREFIX + token;

        return withRetry(() -> redisTemplate.opsForValue().set(redisKey, email, TTL)
                .doOnSuccess(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        log.info("Successfully saved reset token for email: {}", email);
                        meterRegistry.counter("password.reset.token.save.success").increment();
                    } else {
                        log.error("Failed to save reset token for email: {}", email);
                        meterRegistry.counter("password.reset.token.save.failure").increment();
                    }
                })
                .thenReturn(token)
                .doOnError(e -> {
                    log.error("Error saving reset token for email: {}", email, e);
                    meterRegistry.counter("password.reset.token.save.error").increment();
                })
        );
    }

    public Mono<Boolean> tokenExists(String token) {
        if (!StringUtils.hasText(token)) {
            log.warn("Token existence check with empty token");
            return Mono.just(false);
        }

        String redisKey = RESET_PREFIX + token;

        return withRetry(() -> redisTemplate.hasKey(redisKey)
                .doOnNext(exists -> {
                    log.debug("Token {} exists check result: {}", token, exists);
                    if (exists) {
                        meterRegistry.counter("password.reset.token.valid").increment();
                    } else {
                        meterRegistry.counter("password.reset.token.invalid").increment();
                    }
                })
                .doOnError(e -> {
                    log.error("Error checking token existence: {}", token, e);
                    meterRegistry.counter("password.reset.token.check.error").increment();
                })
        );
    }

    public Mono<String> getEmailFromToken(String token) {
        if (!StringUtils.hasText(token)) {
            log.warn("Attempt to get email with empty token");
            return Mono.error(new IllegalArgumentException("Token must not be empty"));
        }

        String redisKey = RESET_PREFIX + token;

        return withRetry(() -> redisTemplate.opsForValue().get(redisKey)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("No email found for token: {}", token);
                    meterRegistry.counter("password.reset.token.email_not_found").increment();
                    return Mono.error(new TokenNotFoundException("Invalid or expired token"));
                }))
                .doOnNext(email -> log.debug("Retrieved email {} for token {}", email, token))
                .doOnError(e -> {
                    if (!(e instanceof TokenNotFoundException)) {
                        log.error("Error retrieving email for token: {}", token, e);
                        meterRegistry.counter("password.reset.token.retrieve.error").increment();
                    }
                })
        );
    }

    public Mono<Boolean> deleteToken(String token) {
        if (!StringUtils.hasText(token)) {
            log.warn("Attempt to delete empty token");
            return Mono.just(false);
        }

        String redisKey = RESET_PREFIX + token;

        return withRetry(() -> redisTemplate.delete(redisKey)
                .map(count -> {
                    boolean deleted = count > 0;
                    log.debug("Token {} deletion result: {}", token, deleted);
                    if (deleted) {
                        meterRegistry.counter("password.reset.token.deletion.success").increment();
                    } else {
                        meterRegistry.counter("password.reset.token.deletion.failure").increment();
                    }
                    return deleted;
                })
                .doOnError(e -> {
                    log.error("Error deleting token: {}", token, e);
                    meterRegistry.counter("password.reset.token.deletion.error").increment();
                })
        );
    }

    private <T> Mono<T> withRetry(Supplier<Mono<T>> operation) {
        return Mono.defer(operation)
                .retryWhen(Retry.backoff(MAX_RETRY_ATTEMPTS, RETRY_DELAY)
                        .filter(e -> e instanceof RedisConnectionFailureException)
                        .doBeforeRetry(rs -> log.warn("Retrying Redis operation after failure (attempt {})", rs.totalRetries()))
                        .onRetryExhaustedThrow((retrySpec, rs) -> {
                            log.error("Redis operation failed after {} attempts", rs.totalRetries());
                            return new RedisOperationException("Failed after " + rs.totalRetries() + " attempts");
                        })
                );
    }

    public Mono<Boolean> invalidateAllTokensForEmail(String email) {
        if (!StringUtils.hasText(email)) {
            log.warn("Attempt to invalidate tokens for empty email");
            return Mono.just(false);
        }

        return redisTemplate.keys(RESET_PREFIX + "*")
                .flatMap(key -> redisTemplate.opsForValue().get(key)
                        .filter(email::equals)
                        .flatMap(__ -> redisTemplate.delete(key))
                )
                .collectList()
                .map(deletions -> !deletions.isEmpty())
                .doOnSuccess(deleted -> {
                    if (deleted) {
                        log.info("Invalidated all tokens for email: {}", email);
                        meterRegistry.counter("password.reset.token.bulk_invalidation.success").increment();
                    } else {
                        log.debug("No tokens found to invalidate for email: {}", email);
                    }
                })
                .doOnError(e -> {
                    log.error("Error invalidating tokens for email: {}", email, e);
                    meterRegistry.counter("password.reset.token.bulk_invalidation.error").increment();
                });
    }

}
