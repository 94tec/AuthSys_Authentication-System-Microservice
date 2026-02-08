package com.techStack.authSys.config.intergration;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.dto.internal.SessionRecord;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.*;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Redis Configuration
 *
 * Configures Redis connection, serialization, and templates.
 * Uses Clock for timestamp tracking and logging.
 */
@Configuration
@Slf4j
public class RedisConfig {

    /* =========================
       Redis Connection Settings
       ========================= */

    @Value("${spring.redis.host}")
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;

    @Value("${spring.redis.password:}")
    private String redisPassword;

    /* =========================
       Pool Configuration
       ========================= */

    @Value("${spring.redis.lettuce.pool.max-active}")
    private int maxTotal;

    @Value("${spring.redis.lettuce.pool.max-idle}")
    private int maxIdle;

    @Value("${spring.redis.lettuce.pool.min-idle}")
    private int minIdle;

    /* =========================
       Timeout Configuration
       ========================= */

    @Value("${spring.redis.timeout:2000}")
    private long commandTimeoutMs;

    /* =========================
       Cache Configuration
       ========================= */

    @Value("${spring.redis.cache.ttl-minutes:10}")
    private long cacheTtlMinutes;

    /* =========================
       Connection Pool
       ========================= */

    /**
     * Configure the connection pool for Lettuce
     */
    @Bean
    public GenericObjectPoolConfig<?> lettucePoolConfig(Clock clock) {
        Instant now = clock.instant();

        log.info("🔧 Configuring Redis connection pool at {}", now);

        GenericObjectPoolConfig<?> poolConfig = new GenericObjectPoolConfig<>();
        poolConfig.setMaxTotal(maxTotal);
        poolConfig.setMaxIdle(maxIdle);
        poolConfig.setMinIdle(minIdle);
        poolConfig.setTestOnBorrow(true);
        poolConfig.setTestWhileIdle(true);
        poolConfig.setBlockWhenExhausted(true);

        log.info("📊 Pool config - MaxTotal: {}, MaxIdle: {}, MinIdle: {}",
                maxTotal, maxIdle, minIdle);

        return poolConfig;
    }

    /* =========================
       Connection Factory
       ========================= */

    /**
     * Primary LettuceConnectionFactory with pooling and validation
     */
    @Bean
    @Primary
    public LettuceConnectionFactory lettuceConnectionFactory(
            GenericObjectPoolConfig<?> poolConfig,
            Clock clock
    ) {
        Instant startTime = clock.instant();

        log.info("🔌 Connecting to Redis at {}:{} (started at {})",
                redisHost, redisPort, startTime);

        // Configure Redis connection
        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration(redisHost, redisPort);

        if (!redisPassword.isEmpty()) {
            redisConfig.setPassword(redisPassword);
            log.debug("🔐 Redis password configured");
        } else {
            log.debug("🔓 No Redis password configured");
        }

        // Configure Lettuce client
        LettuceClientConfiguration clientConfig = LettucePoolingClientConfiguration.builder()
                .commandTimeout(Duration.ofMillis(commandTimeoutMs))
                .shutdownTimeout(Duration.ZERO)
                .poolConfig(poolConfig)
                .build();

        // Create and configure factory
        LettuceConnectionFactory factory = new LettuceConnectionFactory(redisConfig, clientConfig);
        factory.setValidateConnection(true);

        Instant endTime = clock.instant();
        Duration duration = Duration.between(startTime, endTime);

        log.info("✅ Redis connection factory created at {} (duration: {})", endTime, duration);
        log.info("⏱️ Command timeout: {}ms", commandTimeoutMs);

        return factory;
    }

    /* =========================
       Object Mapper
       ========================= */

    /**
     * ObjectMapper configured for Redis serialization/deserialization
     */
    @Bean
    public ObjectMapper redisObjectMapper(Clock clock) {
        Instant now = clock.instant();

        log.info("📝 Configuring Redis ObjectMapper at {}", now);

        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

        log.info("✅ Redis ObjectMapper configured with JavaTimeModule");

        return mapper;
    }

    /* =========================
       Blocking Templates
       ========================= */

    /**
     * Classic RedisTemplate for blocking Redis operations
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(
            LettuceConnectionFactory lettuceConnectionFactory,
            ObjectMapper redisObjectMapper,
            Clock clock
    ) {
        Instant now = clock.instant();

        log.info("🔨 Configuring blocking RedisTemplate at {}", now);

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(lettuceConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer(redisObjectMapper));
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer(redisObjectMapper));
        template.afterPropertiesSet();

        log.info("✅ Blocking RedisTemplate configured with Jackson serialization at {}", now);

        return template;
    }

    /* =========================
       Reactive Templates
       ========================= */

    /**
     * Reactive RedisTemplate for reactive Redis operations with generic Object values
     */
    @Bean
    public ReactiveRedisTemplate<String, Object> reactiveRedisTemplate(
            LettuceConnectionFactory lettuceConnectionFactory,
            ObjectMapper redisObjectMapper,
            Clock clock
    ) {
        Instant now = clock.instant();

        log.info("⚡ Configuring reactive RedisTemplate<String, Object> at {}", now);

        RedisSerializationContext<String, Object> context = RedisSerializationContext
                .<String, Object>newSerializationContext(new StringRedisSerializer())
                .value(new GenericJackson2JsonRedisSerializer(redisObjectMapper))
                .hashKey(new StringRedisSerializer())
                .hashValue(new GenericJackson2JsonRedisSerializer(redisObjectMapper))
                .build();

        ReactiveRedisTemplate<String, Object> template =
                new ReactiveRedisTemplate<>(lettuceConnectionFactory, context);

        log.info("✅ Reactive RedisTemplate<String, Object> configured at {}", now);

        return template;
    }

    /**
     * Reactive RedisTemplate specialized for String values
     */
    @Bean
    public ReactiveRedisTemplate<String, String> reactiveStringRedisTemplate(
            LettuceConnectionFactory lettuceConnectionFactory,
            Clock clock
    ) {
        Instant now = clock.instant();

        log.info("⚡ Configuring reactive RedisTemplate<String, String> at {}", now);

        RedisSerializationContext<String, String> context = RedisSerializationContext
                .<String, String>newSerializationContext(new StringRedisSerializer())
                .value(new StringRedisSerializer())
                .hashKey(new StringRedisSerializer())
                .hashValue(new StringRedisSerializer())
                .build();

        ReactiveRedisTemplate<String, String> template =
                new ReactiveRedisTemplate<>(lettuceConnectionFactory, context);

        log.info("✅ Reactive RedisTemplate<String, String> configured at {}", now);

        return template;
    }

    /* =========================
       Specialized Templates
       ========================= */

    /**
     * Reactive RedisTemplate for SessionRecord objects
     */
    @Bean
    public ReactiveRedisTemplate<String, SessionRecord> sessionRecordRedisTemplate(
            LettuceConnectionFactory lettuceConnectionFactory,
            ObjectMapper redisObjectMapper,
            Clock clock
    ) {
        Instant now = clock.instant();

        log.info("⚡ Configuring reactive RedisTemplate<String, SessionRecord> at {}", now);

        Jackson2JsonRedisSerializer<SessionRecord> serializer =
                new Jackson2JsonRedisSerializer<>(redisObjectMapper, SessionRecord.class);

        RedisSerializationContext<String, SessionRecord> context = RedisSerializationContext
                .<String, SessionRecord>newSerializationContext(new StringRedisSerializer())
                .value(serializer)
                .build();

        ReactiveRedisTemplate<String, SessionRecord> template =
                new ReactiveRedisTemplate<>(lettuceConnectionFactory, context);

        log.info("✅ Reactive RedisTemplate<String, SessionRecord> configured at {}", now);

        return template;
    }

    /**
     * Reactive RedisTemplate for FirebaseToken objects
     */
    /**
     * Configure ReactiveRedisTemplate for FirebaseToken
     */
    @Bean
    public ReactiveRedisTemplate<String, FirebaseToken> firebaseTokenRedisTemplate(
            ReactiveRedisConnectionFactory connectionFactory) {

        // Configure Jackson serializer
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        Jackson2JsonRedisSerializer<FirebaseToken> serializer =
                new Jackson2JsonRedisSerializer<>(objectMapper, FirebaseToken.class);

        // Build serialization context
        RedisSerializationContext<String, FirebaseToken> serializationContext =
                RedisSerializationContext
                        .<String, FirebaseToken>newSerializationContext()
                        .key(new StringRedisSerializer())
                        .value(serializer)
                        .hashKey(new StringRedisSerializer())
                        .hashValue(serializer)
                        .build();

        return new ReactiveRedisTemplate<>(connectionFactory, serializationContext);
    }

    /* =========================
       Cache Configuration
       ========================= */

    /**
     * Redis cache configuration with TTL and Jackson serialization
     */
    @Bean
    public RedisCacheConfiguration cacheConfiguration(
            ObjectMapper redisObjectMapper,
            Clock clock
    ) {
        Instant now = clock.instant();

        log.info("💾 Configuring Redis cache at {}", now);

        RedisCacheConfiguration config = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(cacheTtlMinutes))
                .disableCachingNullValues()
                .serializeValuesWith(RedisSerializationContext.SerializationPair
                        .fromSerializer(new GenericJackson2JsonRedisSerializer(redisObjectMapper)));

        log.info("✅ Redis cache configured with TTL: {} minutes at {}", cacheTtlMinutes, now);

        return config;
    }

    /* =========================
       Health Check
       ========================= */

    /**
     * Redis Health Indicator
     */
    @Bean
    public RedisHealthIndicator redisHealthIndicator(
            LettuceConnectionFactory connectionFactory,
            Clock clock
    ) {
        return new RedisHealthIndicator(connectionFactory, clock);
    }

    /**
     * Redis Health Indicator implementation
     */
    public static class RedisHealthIndicator {

        private final LettuceConnectionFactory connectionFactory;
        private final Clock clock;

        public RedisHealthIndicator(
                LettuceConnectionFactory connectionFactory,
                Clock clock
        ) {
            this.connectionFactory = connectionFactory;
            this.clock = clock;
        }

        /**
         * Check if Redis is healthy
         */
        public boolean isHealthy() {
            Instant checkTime = clock.instant();

            try {
                // Test connection
                connectionFactory.getConnection().ping();

                log.debug("✅ Redis health check passed at {}", checkTime);
                return true;

            } catch (Exception e) {
                log.error("❌ Redis health check failed at {}: {}", checkTime, e.getMessage());
                return false;
            }
        }

        /**
         * Get Redis connection status
         */
        public java.util.Map<String, Object> getStatus() {
            Instant statusTime = clock.instant();

            java.util.Map<String, Object> status = new java.util.HashMap<>();
            status.put("timestamp", statusTime.toString());
            status.put("healthy", isHealthy());
            status.put("validateConnection", connectionFactory.getValidateConnection());

            return status;
        }
    }
}