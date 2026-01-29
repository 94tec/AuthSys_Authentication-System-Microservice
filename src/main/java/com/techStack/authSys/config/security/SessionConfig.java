package com.techStack.authSys.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;

@Configuration
@EnableRedisWebSession // Enables Spring Session backed by Redis for WebFlux
public class SessionConfig {

    @Bean
    public ReactiveRedisOperations<String, Object> sessionRedisOperations(ReactiveRedisConnectionFactory factory) {
        RedisSerializationContext<String, Object> serializationContext = RedisSerializationContext
                .<String, Object>newSerializationContext(new StringRedisSerializer())
                .value(new JdkSerializationRedisSerializer())
                .hashKey(new StringRedisSerializer())
                .hashValue(new JdkSerializationRedisSerializer())
                .build();

        return new ReactiveRedisTemplate<>(factory, serializationContext);
    }
}
