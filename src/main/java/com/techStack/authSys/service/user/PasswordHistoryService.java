package com.techStack.authSys.service.user;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.Query;

import com.techStack.authSys.service.security.EncryptionService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Password History Service
 *
 * Manages password history and reuse validation.
 * Uses Clock for all timestamp operations.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordHistoryService {

    private final Firestore firestore;
    private final EncryptionService encryptionService;
    private final Clock clock;

    /* =========================
       Password Reuse Check
       ========================= */

    /**
     * Check if password has been used before
     */
    public Mono<Boolean> isPasswordReused(String userId, String newPassword) {
        Instant now = clock.instant();

        log.debug("Checking password reuse for user {} at {}", userId, now);

        return Mono.fromCallable(() ->
                        firestore.collection("password_history")
                                .document(userId)
                                .collection("history")
                                .orderBy("createdAt", Query.Direction.DESCENDING)
                                .limit(5)
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .flatMapMany(querySnapshot -> Flux.fromIterable(querySnapshot.getDocuments()))
                .publishOn(Schedulers.boundedElastic())
                .map(doc -> {
                    String encryptedPassword = doc.getString("password");
                    return encryptionService.decrypt(encryptedPassword);
                })
                .any(decrypted -> decrypted.equals(newPassword))
                .doOnSuccess(isReused -> {
                    if (isReused) {
                        log.warn("Password reuse detected for user {} at {}", userId, now);
                    } else {
                        log.debug("Password is unique for user {} at {}", userId, now);
                    }
                })
                .doOnError(e -> log.error("Error checking password reuse for user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /* =========================
       Password History Storage
       ========================= */

    /**
     * Save password to history
     */
    public Mono<Void> saveToHistory(String userId, String plainPassword) {
        Instant now = clock.instant();

        log.debug("Saving password to history for user {} at {}", userId, now);

        return Mono.fromCallable(() -> {
                    String encrypted = encryptionService.encrypt(plainPassword);

                    Map<String, Object> entry = new HashMap<>();
                    entry.put("password", encrypted);
                    entry.put("createdAt", Timestamp.ofTimeSecondsAndNanos(
                            now.getEpochSecond(), now.getNano()));
                    entry.put("userId", userId);

                    return firestore.collection("password_history")
                            .document(userId)
                            .collection("history")
                            .document(UUID.randomUUID().toString())
                            .set(entry);
                })
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .doOnSuccess(v -> log.debug("Saved password to history for user {} at {}",
                        userId, now))
                .doOnError(e -> log.error("Error saving password history for user {} at {}: {}",
                        userId, now, e.getMessage()))
                .then();
    }

    /* =========================
       Password History Retrieval
       ========================= */

    /**
     * Get password history count for user
     */
    public Mono<Long> getPasswordHistoryCount(String userId) {
        Instant now = clock.instant();

        return Mono.fromCallable(() ->
                        firestore.collection("password_history")
                                .document(userId)
                                .collection("history")
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .map(querySnapshot -> (long) querySnapshot.size())
                .doOnSuccess(count -> log.debug("User {} has {} password history entries at {}",
                        userId, count, now))
                .doOnError(e -> log.error("Error getting password history count for user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /**
     * Get last password change time
     */
    public Mono<Instant> getLastPasswordChangeTime(String userId) {
        Instant now = clock.instant();

        return Mono.fromCallable(() ->
                        firestore.collection("password_history")
                                .document(userId)
                                .collection("history")
                                .orderBy("createdAt", Query.Direction.DESCENDING)
                                .limit(1)
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .flatMap(querySnapshot -> {
                    if (querySnapshot.isEmpty()) {
                        log.debug("No password history found for user {} at {}", userId, now);
                        return Mono.empty();
                    }

                    Timestamp timestamp = querySnapshot.getDocuments().get(0)
                            .getTimestamp("createdAt");

                    if (timestamp == null) {
                        return Mono.empty();
                    }

                    Instant changeTime = Instant.ofEpochSecond(
                            timestamp.getSeconds(), timestamp.getNanos());

                    log.debug("Last password change for user {} was at {}", userId, changeTime);
                    return Mono.just(changeTime);
                })
                .doOnError(e -> log.error("Error getting last password change time for user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /* =========================
       Password History Cleanup
       ========================= */

    /**
     * Delete password history for user
     */
    public Mono<Void> deletePasswordHistory(String userId) {
        Instant now = clock.instant();

        log.info("Deleting password history for user {} at {}", userId, now);

        return Mono.fromCallable(() ->
                        firestore.collection("password_history")
                                .document(userId)
                                .collection("history")
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .flatMapMany(querySnapshot -> Flux.fromIterable(querySnapshot.getDocuments()))
                .flatMap(doc -> Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(doc.getReference().delete())))
                .then()
                .doOnSuccess(v -> log.info("Deleted password history for user {} at {}",
                        userId, now))
                .doOnError(e -> log.error("Error deleting password history for user {} at {}: {}",
                        userId, now, e.getMessage()));
    }

    /**
     * Delete old password history entries (keep last N)
     */
    public Mono<Void> deleteOldPasswordHistory(String userId, int keepCount) {
        Instant now = clock.instant();

        log.debug("Deleting old password history for user {} (keeping last {}) at {}",
                userId, keepCount, now);

        return Mono.fromCallable(() ->
                        firestore.collection("password_history")
                                .document(userId)
                                .collection("history")
                                .orderBy("createdAt", Query.Direction.DESCENDING)
                                .offset(keepCount)
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .flatMapMany(querySnapshot -> Flux.fromIterable(querySnapshot.getDocuments()))
                .flatMap(doc -> Mono.fromFuture(
                        FirestoreUtil.toCompletableFuture(doc.getReference().delete())))
                .then()
                .doOnSuccess(v -> log.debug("Cleaned up old password history for user {} at {}",
                        userId, now))
                .doOnError(e -> log.error("Error cleaning up password history for user {} at {}: {}",
                        userId, now, e.getMessage()));
    }
}