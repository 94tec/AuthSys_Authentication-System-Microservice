package com.techStack.authSys.service;

import com.google.cloud.firestore.*;
import com.techStack.authSys.exception.CacheOperationException;
import com.techStack.authSys.models.RateLimitRecord;
import com.techStack.authSys.util.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class CacheService {

    private static final String RATE_LIMIT_COLLECTION = "auth_rate_limits";
    private final Firestore firestore;
    private final RedisTemplate<String, Object> redisTemplate;
    private final AuditLogService auditLogService;

    @Value("${cache.rate-limit.ttl.minutes:5}")
    private int rateLimitTtlMinutes;

    @Value("${cache.rate-limit.redis.prefix:rate_limit:}")
    private String redisRateLimitPrefix;

    /**
     * Gets rate limit record with multi-layer caching
     */
    public Mono<RateLimitRecord> getRateLimitRecord(String identifier, String type) {
        String cacheKey = STR."\{redisRateLimitPrefix}\{type}:\{identifier}";

        return Mono.defer(() -> {
                    // 1. First try Redis cache
                    return getFromRedisCache(cacheKey)
                            .flatMap(cachedRecord -> {
                                if (cachedRecord != null) {
                                    return Mono.just(cachedRecord);
                                }
                                // 2. Fallback to Firestore
                                return getFromFirestore(identifier)
                                        .flatMap(record -> {
                                            // 3. Update Redis cache
                                            return cacheInRedis(cacheKey, record)
                                                    .thenReturn(record);
                                        });
                            });
                }).subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    log.error("Failed to get rate limit record for {}: {}", identifier, e.getMessage());
                    auditLogService.logCacheEvent("RATE_LIMIT_READ_FAILURE", identifier, e.getMessage());
                    return Mono.error(new CacheOperationException("Failed to retrieve rate limit record"));
                });
    }

    /**
     * Updates rate limit counts with transaction support
     */
    public Mono<Void> updateRateLimitCounts(String ipAddress, String email,
                                            RateLimitRecord ipRecord, RateLimitRecord emailRecord) {
        return Mono.defer(() ->
                Mono.fromCallable(() -> firestore.runTransaction(transaction -> {
                            DocumentReference ipRef = firestore.collection(RATE_LIMIT_COLLECTION).document(ipAddress);
                            DocumentReference emailRef = firestore.collection(RATE_LIMIT_COLLECTION).document(email);

                            try {
                                // Get current records
                                DocumentSnapshot ipDoc = transaction.get(ipRef).get();
                                DocumentSnapshot emailDoc = transaction.get(emailRef).get();

                                // Update counts
                                RateLimitRecord updatedIpRecord = updateRecord(ipDoc, ipRecord);
                                RateLimitRecord updatedEmailRecord = updateRecord(emailDoc, emailRecord);

                                // Set in transaction
                                transaction.set(ipRef, updatedIpRecord);
                                transaction.set(emailRef, updatedEmailRecord);

                                // Return updated records
                                return Map.of("ip", updatedIpRecord, "email", updatedEmailRecord);
                            } catch (Exception e) {
                                throw new RuntimeException("Failed to update rate limits", e);
                            }
                        }))
                        .flatMap(result -> {
                            // Extract updated records
                            RateLimitRecord updatedIpRecord = null;
                            try {
                                updatedIpRecord = (RateLimitRecord) result.get();
                            } catch (InterruptedException e) {
                                throw new RuntimeException(e);
                            } catch (ExecutionException e) {
                                throw new RuntimeException(e);
                            }
                            RateLimitRecord updatedEmailRecord = null;
                            try {
                                updatedEmailRecord = (RateLimitRecord) result.get();
                            } catch (InterruptedException e) {
                                throw new RuntimeException(e);
                            } catch (ExecutionException e) {
                                throw new RuntimeException(e);
                            }

                            // Update Redis cache
                            String ipCacheKey = redisRateLimitPrefix + "ip:" + ipAddress;
                            String emailCacheKey = redisRateLimitPrefix + "email:" + email;

                            return Mono.zip(
                                    cacheInRedis(ipCacheKey, updatedIpRecord),
                                    cacheInRedis(emailCacheKey, updatedEmailRecord)
                            ).then();
                        })
                        .subscribeOn(Schedulers.boundedElastic()) // Run on boundedElastic for blocking Firestore ops
                        .onErrorResume(e -> {
                            log.error("Failed to update rate limit counts: {}", e.getMessage());
                            auditLogService.logCacheEvent("RATE_LIMIT_UPDATE_FAILURE",
                                    ipAddress + "|" + email, e.getMessage());
                            return Mono.error(new CacheOperationException("Failed to update rate limits"));
                        })
        );
    }


    /**
     * Updates single rate limit record with consistency checks
     */
    public Mono<Void> updateRateLimitRecord(String identifier, String type, RateLimitRecord record) {
        String cacheKey = redisRateLimitPrefix + type + ":" + identifier;

        return Mono.defer(() -> {
                    // Convert Firestore ApiFuture to CompletableFuture
                    CompletableFuture<WriteResult> future = FirestoreUtil.toCompletableFuture(
                            firestore.collection(RATE_LIMIT_COLLECTION)
                                    .document(identifier)
                                    .set(record, SetOptions.merge())
                    );

                    return Mono.fromFuture(future)  // 1. Update Firestore
                            .then(cacheInRedis(cacheKey, record))  // 2. Update Redis
                            .doOnSuccess(v -> log.debug("Updated rate limit record for {}", identifier));
                })
                .subscribeOn(Schedulers.boundedElastic()) // Run on boundedElastic thread pool
                .onErrorResume(e -> {
                    log.error("Failed to update rate limit record for {}: {}", identifier, e.getMessage());
                    auditLogService.logCacheEvent("RATE_LIMIT_UPDATE_FAILURE", identifier, e.getMessage());
                    return Mono.error(new CacheOperationException("Failed to update rate limit record"));
                });
    }

    // Helper methods
    private Mono<RateLimitRecord> getFromRedisCache(String key) {
        return Mono.fromCallable(() ->
                (RateLimitRecord) redisTemplate.opsForValue().get(key)
        ).onErrorResume(e -> {
            log.warn("Redis cache read failed for {}: {}", key, e.getMessage());
            return Mono.empty();
        });
    }

    private Mono<Void> cacheInRedis(String key, RateLimitRecord record) {
        return Mono.fromRunnable(() ->
                redisTemplate.opsForValue().set(
                        key,
                        record,
                        rateLimitTtlMinutes,
                        TimeUnit.MINUTES
                )
        ).onErrorResume(e -> {
            log.warn("Failed to cache in Redis: {}", e.getMessage());
            return Mono.empty();
        }).then();
    }

    private Mono<RateLimitRecord> getFromFirestore(String identifier) {
        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(
                        firestore.collection(RATE_LIMIT_COLLECTION)
                                .document(identifier)
                                .get()
                ))
                .map(documentSnapshot -> {
                    if (!documentSnapshot.exists()) {
                        return new RateLimitRecord(identifier);
                    }
                    RateLimitRecord record = documentSnapshot.toObject(RateLimitRecord.class);
                    return record != null ? record : new RateLimitRecord(identifier);
                })
                .subscribeOn(Schedulers.boundedElastic()); // Run on a non-blocking thread pool
    }


    private RateLimitRecord updateRecord(DocumentSnapshot doc, RateLimitRecord newRecord) {
        RateLimitRecord existing = doc.exists() ?
                doc.toObject(RateLimitRecord.class) : new RateLimitRecord();
        if (existing == null) {
            existing = new RateLimitRecord();
        }

        // Reset counts if outside time windows
        Instant now = Instant.now();
        if (existing.getLastAttempt().isBefore(now.minus(1, ChronoUnit.MINUTES))) {
            existing.resetMinuteCount();
        }
        if (existing.getLastAttempt().isBefore(now.minus(1, ChronoUnit.HOURS))) {
            existing.resetHourCount();
        }

        // Update counts
        existing.incrementMinuteCount();
        existing.incrementHourCount();
        existing.setLastAttempt(now);

        return existing;
    }

    /**
     * Scheduled cleanup of expired rate limit records
     */
    @Scheduled(fixedRate = 3600000) // Every hour
    public void cleanupOldRecords() {
        Instant cutoff = Instant.now().minus(24, ChronoUnit.HOURS);

        FirestoreUtil.toCompletableFuture(
                firestore.collection(RATE_LIMIT_COLLECTION)
                        .whereLessThan("lastAttempt", cutoff)
                        .get()
        ).thenAccept(querySnapshot -> {
            if (!querySnapshot.isEmpty()) {
                WriteBatch batch = firestore.batch();
                querySnapshot.getDocuments().forEach(doc -> {
                    batch.delete(doc.getReference());
                    redisTemplate.delete(redisRateLimitPrefix + doc.getId());
                });
                batch.commit()
                        .addListener(() -> log.info("Cleaned up {} old rate limit records", querySnapshot.size()),
                                Runnable::run);
            }
        }).exceptionally(e -> {
            log.error("Error cleaning up old rate limit records: {}", e.getMessage());
            return null;
        });
    }
}