package com.techStack.authSys.identity.controller;

import com.techStack.authSys.identity.repository.FirestoreUserRepository;
import com.techStack.authSys.identity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import javax.sql.DataSource;
import java.sql.Connection;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CompletableFuture;

@Slf4j
@RestController
@RequestMapping("/api/admin/system")
@RequiredArgsConstructor
public class AdminSystemController {

    private final DataSource dataSource;
    private final RedisTemplate<String, String> redisTemplate;
    private final com.google.cloud.firestore.Firestore firestore;
    private final FirestoreUserRepository userRepository;
    // inject whatever scheduler registry / TaskScheduler you already use
    // private final ScheduledAnnotationBeanPostProcessor scheduledTasks;

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        long start = System.currentTimeMillis();

        CompletableFuture<ServiceCheck> postgres = CompletableFuture.supplyAsync(this::checkPostgres);
        CompletableFuture<ServiceCheck> redis = CompletableFuture.supplyAsync(this::checkRedis);
        CompletableFuture<ServiceCheck> firestoreCheck = CompletableFuture.supplyAsync(this::checkFirestore);

        CompletableFuture.allOf(postgres, redis, firestoreCheck).join();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("checkDurationMs", System.currentTimeMillis() - start);
        body.put("services", List.of(
                serviceEntry("Relational DB", "PostgreSQL via HikariPool", postgres.join()),
                serviceEntry("Cache / sessions", "Redis localhost:6379", redis.join()),
                serviceEntry("Document DB", "Firestore", firestoreCheck.join())
        ));
        return ResponseEntity.ok(body);
    }

    @GetMapping("/roles")
    public Mono<ResponseEntity<List<Map<String, Object>>>> roleCounts() {
        return userRepository.countUsersGroupedByRole()
                .map(counts -> {
                    List<Map<String, Object>> result = new ArrayList<>();
                    counts.forEach((role, count) -> {
                        if (count > 0) { // skip unused roles instead of padding zeros
                            result.add(Map.of("role", role.name(), "count", count));
                        }
                    });
                    result.sort((a, b) -> ((Long) b.get("count")).compareTo((Long) a.get("count")));
                    return ResponseEntity.ok(result);
                });
    }

    private ServiceCheck checkPostgres() {
        long t0 = System.currentTimeMillis();
        try (Connection c = dataSource.getConnection()) {
            boolean ok = c.isValid(2); // 2s timeout
            return new ServiceCheck(ok ? "up" : "down", System.currentTimeMillis() - t0, null);
        } catch (Exception e) {
            return new ServiceCheck("down", System.currentTimeMillis() - t0, e.getMessage());
        }
    }

    private ServiceCheck checkRedis() {
        long t0 = System.currentTimeMillis();
        try {
            String pong = redisTemplate.getConnectionFactory().getConnection().ping();
            return new ServiceCheck("up".equalsIgnoreCase(pong) || pong != null ? "up" : "down",
                    System.currentTimeMillis() - t0, null);
        } catch (Exception e) {
            return new ServiceCheck("down", System.currentTimeMillis() - t0, e.getMessage());
        }
    }

    private ServiceCheck checkFirestore() {
        long t0 = System.currentTimeMillis();
        try {
            firestore.collection("_health").document("ping").get().get();
            return new ServiceCheck("up", System.currentTimeMillis() - t0, null);
        } catch (Exception e) {
            return new ServiceCheck("down", System.currentTimeMillis() - t0, e.getMessage());
        }
    }

    private Map<String, Object> serviceEntry(String label, String detail, ServiceCheck check) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("label", label);
        m.put("detail", detail);
        m.put("status", check.status);
        m.put("latencyMs", check.latencyMs);
        if (check.error != null) m.put("error", check.error);
        return m;
    }

    private record ServiceCheck(String status, long latencyMs, String error) {}
}