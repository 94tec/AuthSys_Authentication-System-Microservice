package com.techStack.authSys.service.authorization;

import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.repository.authorization.FirestoreRolePermissionsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

/**
 * Eagerly warms the Redis RBAC cache at startup.
 *
 * Called by PermissionSeeder after seeding completes.
 * Ensures first request for any role hits Redis, not Firestore.
 * TTL matches your existing RedisConfig cache TTL (10 minutes).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionCacheWarmupService {

    private static final Duration CACHE_TTL = Duration.ofMinutes(10);
    private static final String KEY_PREFIX = "rbac:role:";

    private final FirestoreRolePermissionsRepository rolePermissionsRepo;
    private final ReactiveRedisTemplate<String, Object> reactiveRedisTemplate;

    public Mono<Void> warmPermissions() {
        log.info("🔥 Warming RBAC permission cache for {} roles...", Roles.values().length);

        return Flux.fromArray(Roles.values())
                .flatMap(role -> Mono.fromCallable(() -> {
                            List<String> perms = rolePermissionsRepo
                                    .findByRoleNameBlocking(role.name());

                            String key = KEY_PREFIX + role.name();

                            return reactiveRedisTemplate
                                    .opsForValue()
                                    .set(key, perms, CACHE_TTL)
                                    .doOnSuccess(v -> log.info(
                                            "  ✅ Cached {} permissions for {}",
                                            perms.size(), role.name()))
                                    .then();
                        })
                        .flatMap(m -> m)
                        .subscribeOn(Schedulers.boundedElastic()))
                .then()
                .doOnSuccess(v -> log.info(
                        "✅ RBAC cache warmup complete — {} roles cached",
                        Roles.values().length))
                .doOnError(e -> log.error(
                        "❌ RBAC cache warmup failed: {}", e.getMessage(), e));
    }
}