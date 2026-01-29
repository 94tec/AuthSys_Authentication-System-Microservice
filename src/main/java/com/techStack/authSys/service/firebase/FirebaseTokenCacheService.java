package com.techStack.authSys.service.firebase;

import com.google.firebase.auth.FirebaseToken;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Service
public class FirebaseTokenCacheService {

    private final ReactiveRedisTemplate<String, FirebaseToken> redisTemplate;
    private final Duration ttl = Duration.ofMinutes(30);

    public FirebaseTokenCacheService(ReactiveRedisTemplate<String, FirebaseToken> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    private String cacheKey(String token) {
        return STR."firebase-token:\{DigestUtils.sha256Hex(token)}";
    }

    public Mono<FirebaseToken> getCachedToken(String token) {
        return redisTemplate.opsForValue().get(cacheKey(token));
    }

    public Mono<Boolean> cacheToken(String token, FirebaseToken firebaseToken) {
        return redisTemplate.opsForValue()
                .set(cacheKey(token), firebaseToken, ttl);
    }
}

