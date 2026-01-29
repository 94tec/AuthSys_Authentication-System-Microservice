package com.techStack.authSys.config.intergration;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.dto.internal.SessionRecord;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettucePoolingClientConfiguration;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.*;

import java.time.Duration;

@Configuration
public class RedisConfig {

    private static final Logger logger = LoggerFactory.getLogger(RedisConfig.class);

    @Value("${spring.redis.host}")
    private String redisHost;

    @Value("${spring.redis.port}")
    private int redisPort;

    @Value("${spring.redis.password:}") // optional password
    private String redisPassword;

    /**
     * Configure the connection pool for Lettuce.
     */
    @Bean
    public GenericObjectPoolConfig<?> lettucePoolConfig() {
        GenericObjectPoolConfig<?> poolConfig = new GenericObjectPoolConfig<>();
        poolConfig.setMaxTotal(20);      // max total connections
        poolConfig.setMaxIdle(10);       // max idle connections
        poolConfig.setMinIdle(5);        // min idle connections
        poolConfig.setTestOnBorrow(true);
        poolConfig.setTestWhileIdle(true);
        poolConfig.setBlockWhenExhausted(true);
        return poolConfig;
    }

    /**
     * Primary LettuceConnectionFactory bean with pooling and validation.
     * Shared for both reactive and non-reactive Redis templates.
     */
    @Bean
    @Primary
    public LettuceConnectionFactory lettuceConnectionFactory(GenericObjectPoolConfig<?> poolConfig) {
        logger.info("Connecting to Redis at {}:{}", redisHost, redisPort);

        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration(redisHost, redisPort);
        if (!redisPassword.isEmpty()) {
            redisConfig.setPassword(redisPassword);
        }

        LettuceClientConfiguration clientConfig = LettucePoolingClientConfiguration.builder()
                .commandTimeout(Duration.ofSeconds(2))
                .shutdownTimeout(Duration.ZERO)
                .poolConfig(poolConfig)
                .build();

        LettuceConnectionFactory factory = new LettuceConnectionFactory(redisConfig, clientConfig);
        factory.setValidateConnection(true);
        return factory;
    }

    /**
     * ObjectMapper configured for Redis serialization/deserialization.
     */
    @Bean
    public ObjectMapper redisObjectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
    }

    /**
     * Classic RedisTemplate for blocking Redis operations.
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(LettuceConnectionFactory lettuceConnectionFactory,
                                                       ObjectMapper redisObjectMapper) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(lettuceConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer(redisObjectMapper));
        template.setHashKeySerializer(new StringRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer(redisObjectMapper));
        template.afterPropertiesSet();
        logger.info("Configured RedisTemplate with Jackson serialization");
        return template;
    }

    /**
     * Reactive RedisTemplate for reactive Redis operations with generic Object values.
     */
    @Bean
    public ReactiveRedisTemplate<String, Object> reactiveRedisTemplate(
            LettuceConnectionFactory lettuceConnectionFactory,
            ObjectMapper redisObjectMapper) {

        RedisSerializationContext<String, Object> context = RedisSerializationContext
                .<String, Object>newSerializationContext(new StringRedisSerializer())
                .value(new GenericJackson2JsonRedisSerializer(redisObjectMapper))
                .hashKey(new StringRedisSerializer())
                .hashValue(new GenericJackson2JsonRedisSerializer(redisObjectMapper))
                .build();

        return new ReactiveRedisTemplate<>(lettuceConnectionFactory, context);
    }

    /**
     * Reactive RedisTemplate specialized for String values.
     */
    @Bean
    public ReactiveRedisTemplate<String, String> reactiveStringRedisTemplate(LettuceConnectionFactory lettuceConnectionFactory) {
        RedisSerializationContext<String, String> context = RedisSerializationContext
                .<String, String>newSerializationContext(new StringRedisSerializer())
                .value(new StringRedisSerializer())
                .hashKey(new StringRedisSerializer())
                .hashValue(new StringRedisSerializer())
                .build();

        return new ReactiveRedisTemplate<>(lettuceConnectionFactory, context);
    }

    /**
     * Reactive RedisTemplate for SessionRecord objects.
     */
    @Bean
    public ReactiveRedisTemplate<String, SessionRecord> sessionRecordRedisTemplate(
            LettuceConnectionFactory lettuceConnectionFactory,
            ObjectMapper redisObjectMapper) {

        Jackson2JsonRedisSerializer<SessionRecord> serializer =
                new Jackson2JsonRedisSerializer<>(redisObjectMapper, SessionRecord.class);

        RedisSerializationContext<String, SessionRecord> context = RedisSerializationContext
                .<String, SessionRecord>newSerializationContext(new StringRedisSerializer())
                .value(serializer)
                .build();

        return new ReactiveRedisTemplate<>(lettuceConnectionFactory, context);
    }

    /**
     * Reactive RedisTemplate for FirebaseToken objects.
     */
    @Bean
    public ReactiveRedisTemplate<String, FirebaseToken> firebaseTokenRedisTemplate(
            LettuceConnectionFactory lettuceConnectionFactory,
            ObjectMapper redisObjectMapper) {

        Jackson2JsonRedisSerializer<FirebaseToken> serializer =
                new Jackson2JsonRedisSerializer<>(redisObjectMapper, FirebaseToken.class);

        RedisSerializationContext<String, FirebaseToken> context = RedisSerializationContext
                .<String, FirebaseToken>newSerializationContext(new StringRedisSerializer())
                .value(serializer)
                .build();

        return new ReactiveRedisTemplate<>(lettuceConnectionFactory, context);
    }

    /**
     * Redis cache configuration with 10 minutes TTL and Jackson serialization.
     */
    @Bean
    public RedisCacheConfiguration cacheConfiguration(ObjectMapper redisObjectMapper) {
        return RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(10))
                .disableCachingNullValues()
                .serializeValuesWith(RedisSerializationContext.SerializationPair
                        .fromSerializer(new GenericJackson2JsonRedisSerializer(redisObjectMapper)));
    }
}
