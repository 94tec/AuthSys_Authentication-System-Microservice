package com.techStack.authSys.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class BootstrapFlagService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final FirebaseServiceAuth firebaseServiceAuth;

    private static final String BOOTSTRAP_KEY = "bootstrap:super_admin:completed";
    private static final Duration TTL = Duration.ofDays(365 * 2); // long expiration
    private static final String COLLECTION = "system_flags";
    private static final String DOCUMENT_ID = "bootstrap_admin";


    public Mono<Boolean> isBootstrapCompleted() {
        return Mono.fromCallable(() -> redisTemplate.hasKey(BOOTSTRAP_KEY))
                .flatMap(redisHasKey -> {
                    if (Boolean.TRUE.equals(redisHasKey)) {
                        return Mono.just(true); // found in Redis ✅
                    }

                    // Redis didn't have it, fallback to Firestore
                    return firebaseServiceAuth.getDocument(COLLECTION, DOCUMENT_ID)
                            .map(doc -> doc.containsKey("completed") && Boolean.TRUE.equals(doc.get("completed")))
                            .defaultIfEmpty(false)
                            .doOnNext(found -> {
                                if (found) {
                                    // If found in Firestore, cache it to Redis for next time
                                    redisTemplate.opsForValue().set(BOOTSTRAP_KEY, true, TTL);
                                }
                            });
                })
                .onErrorReturn(false); // fallback if Redis/Firestore errors
    }

    public Mono<Void> markBootstrapComplete() {
        Map<String, Object> data = Map.of(
                "completed", true,
                "timestamp", System.currentTimeMillis()
        );
        return firebaseServiceAuth.setDocument(COLLECTION, DOCUMENT_ID, data)
                .then(Mono.fromRunnable(() ->
                        redisTemplate.opsForValue().set(BOOTSTRAP_KEY, true, TTL)
                ));
    }
}
