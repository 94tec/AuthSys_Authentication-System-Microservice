package com.techStack.authSys.service.cache;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
public class ResilientRedisCacheService {
    private final ReactiveRedisTemplate<String, Object> redisTemplate;
    private final CircuitBreaker redisCircuitBreaker;

    public ResilientRedisCacheService(ReactiveRedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.redisCircuitBreaker = CircuitBreaker.ofDefaults("redis");
    }

    public Mono<Object> getWithCircuitBreaker(String key) {
        return redisTemplate.opsForValue()
                .get(key)
                .transformDeferred(CircuitBreakerOperator.of(redisCircuitBreaker))
                .doOnError(error -> log.warn("Redis fallback triggered: {}", error.getMessage()));
    }
}
