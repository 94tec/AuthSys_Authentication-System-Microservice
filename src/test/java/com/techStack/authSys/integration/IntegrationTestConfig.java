package com.techStack.authSys.integration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration Test Configuration with Testcontainers
 *
 * Provides containerized dependencies for integration tests:
 * - Redis (for caching and rate limiting)
 * - Firestore Emulator (for database operations)
 *
 * @author TechStack Testing Team
 * @version 1.0
 */
@TestConfiguration
public class IntegrationTestConfig {

    private static final GenericContainer<?> REDIS_CONTAINER;
    private static final GenericContainer<?> FIRESTORE_CONTAINER;

    static {
        // Redis Container
        REDIS_CONTAINER = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                .withExposedPorts(6379)
                .withReuse(true)
                .waitingFor(Wait.forLogMessage(".*Ready to accept connections.*", 1));
        
        REDIS_CONTAINER.start();

        // Firestore Emulator Container
        FIRESTORE_CONTAINER = new GenericContainer<>(
                DockerImageName.parse("gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators"))
                .withExposedPorts(8080)
                .withCommand("gcloud", "beta", "emulators", "firestore", "start", 
                        "--host-port=0.0.0.0:8080")
                .withReuse(true)
                .waitingFor(Wait.forLogMessage(".*Dev App Server is now running.*", 1));
        
        FIRESTORE_CONTAINER.start();
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        // Redis properties
        registry.add("spring.redis.host", REDIS_CONTAINER::getHost);
        registry.add("spring.redis.port", 
                () -> REDIS_CONTAINER.getMappedPort(6379).toString());

        // Firestore properties
        registry.add("spring.cloud.gcp.firestore.emulator.enabled", () -> "true");
        registry.add("spring.cloud.gcp.firestore.host-port", 
                () -> FIRESTORE_CONTAINER.getHost() + ":" + 
                      FIRESTORE_CONTAINER.getMappedPort(8080));
    }

    @Bean
    public GenericContainer<?> redisContainer() {
        return REDIS_CONTAINER;
    }

    @Bean
    public GenericContainer<?> firestoreContainer() {
        return FIRESTORE_CONTAINER;
    }
}