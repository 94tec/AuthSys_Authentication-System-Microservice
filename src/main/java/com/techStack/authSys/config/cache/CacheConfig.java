package com.techStack.authSys.config.cache;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.cache.support.CompositeCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Unified cache configuration that integrates with existing RedisConfig.
 *
 * ARCHITECTURE:
 * - Primary: CompositeCacheManager (Caffeine L1 + Redis L2)
 * - Caffeine: Fast local cache for permissions and frequently accessed data
 * - Redis: Distributed cache using existing RedisConfig setup
 */
@Configuration
@EnableCaching
public class CacheConfig {

    @Value("${permissions.cache.ttl:300}")
    private long permissionCacheTtl;

    @Value("${permissions.cache.max-size:1000}")
    private long permissionCacheMaxSize;

    /**
     * PRIMARY CACHE MANAGER
     * Uses CompositeCacheManager for two-level caching:
     * 1. Caffeine (L1) - checked first for fast local access
     * 2. Redis (L2) - checked second for distributed data
     */
    @Bean
    @Primary
    public CacheManager compositeCacheManager(
            RedisConnectionFactory redisConnectionFactory,
            @Qualifier("cacheConfiguration") RedisCacheConfiguration baseCacheConfig) {

        CompositeCacheManager compositeCacheManager = new CompositeCacheManager(
                caffeineCacheManager(),                                     // L1: Local
                redisCacheManager(redisConnectionFactory, baseCacheConfig)  // L2: Distributed
        );

        compositeCacheManager.setFallbackToNoOpCache(false);
        return compositeCacheManager;
    }

    /**
     * REDIS CACHE MANAGER (L2 - Distributed)
     * Reuses RedisConnectionFactory from existing RedisConfig
     *
     * Cache strategy by data type:
     * - Permissions: 10 min (stable data)
     * - Users: 5 min (moderately changing)
     * - Sessions: 30 min (active data)
     * - Tokens: 15 min (temporary data)
     *
     * Note: Uses RedisCacheConfiguration from RedisConfig via @Qualifier
     */
    @Bean
    public RedisCacheManager redisCacheManager(
            RedisConnectionFactory redisConnectionFactory,
            @Qualifier("cacheConfiguration") RedisCacheConfiguration baseCacheConfig) {

        // Default configuration for all Redis caches
        // Reuse the base configuration from RedisConfig and customize
        RedisCacheConfiguration defaultConfig = baseCacheConfig
                .prefixCacheNameWith("authSys:cache:"); // Add prefix to avoid collisions

        // Per-cache TTL configurations
        Map<String, RedisCacheConfiguration> cacheConfigurations = new HashMap<>();

        // ========== PERMISSION CACHES (10 min - stable) ==========
        cacheConfigurations.put("rolePermissions",
                defaultConfig.entryTtl(Duration.ofMinutes(10)));
        cacheConfigurations.put("effectivePermissions",
                defaultConfig.entryTtl(Duration.ofMinutes(10)));
        cacheConfigurations.put("userPermissions",
                defaultConfig.entryTtl(Duration.ofMinutes(10)));

        // ========== USER CACHES (5 min - moderately changing) ==========
        cacheConfigurations.put("users",
                defaultConfig.entryTtl(Duration.ofMinutes(5)));
        cacheConfigurations.put("usersByEmail",
                defaultConfig.entryTtl(Duration.ofMinutes(5)));
        cacheConfigurations.put("usersByStatus",
                defaultConfig.entryTtl(Duration.ofMinutes(3)));

        // ========== SESSION CACHES (30 min - active data) ==========
        cacheConfigurations.put("activeSessions",
                defaultConfig.entryTtl(Duration.ofMinutes(30)));
        cacheConfigurations.put("deviceFingerprints",
                defaultConfig.entryTtl(Duration.ofMinutes(30)));

        // ========== TOKEN CACHES (15 min - temporary) ==========
        cacheConfigurations.put("verificationTokens",
                defaultConfig.entryTtl(Duration.ofMinutes(15)));
        cacheConfigurations.put("passwordResetTokens",
                defaultConfig.entryTtl(Duration.ofMinutes(15)));

        // ========== AUDIT & SECURITY (shorter TTL) ==========
        cacheConfigurations.put("loginAttempts",
                defaultConfig.entryTtl(Duration.ofMinutes(5)));
        cacheConfigurations.put("rateLimits",
                defaultConfig.entryTtl(Duration.ofMinutes(1)));

        return RedisCacheManager.builder(redisConnectionFactory)
                .cacheDefaults(defaultConfig)
                .withInitialCacheConfigurations(cacheConfigurations)
                .transactionAware() // Support Spring transactions
                .build();
    }

    /**
     * CAFFEINE CACHE MANAGER (L1 - Local)
     * Fast in-memory cache for frequently accessed data
     *
     * Use cases:
     * - Permission lookups (high read frequency)
     * - Computed effective permissions
     * - Role definitions (rarely change)
     */
    @Bean
    public CacheManager caffeineCacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(
                "rolePermissions",      // Permission definitions by role
                "effectivePermissions", // Computed user permissions
                "userPermissions"       // Direct user permission grants
        );

        cacheManager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(permissionCacheTtl, TimeUnit.SECONDS)  // Write-based expiry
                .expireAfterAccess(180, TimeUnit.SECONDS)                // Access-based expiry
                .maximumSize(permissionCacheMaxSize)                     // Max entries
                .recordStats());                                         // Enable metrics

        return cacheManager;
    }

    /**
     * OPTIONAL: Separate Caffeine cache for ultra-fast session checks
     * Very short TTL, higher throughput
     */
    @Bean
    public CacheManager sessionCaffeineCacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(
                "recentLoginAttempts",  // Rate limiting
                "activeTokenChecks"     // Token validation cache
        );

        cacheManager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(2, TimeUnit.MINUTES)   // Very short TTL
                .expireAfterAccess(1, TimeUnit.MINUTES)  // Remove if idle
                .maximumSize(500)
                .recordStats());

        return cacheManager;
    }
}