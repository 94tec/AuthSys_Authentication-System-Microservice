package com.techStack.authSys.config.intergration;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.cloud.FirestoreClient;
import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import reactor.netty.http.client.HttpClient;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

@Getter
@Configuration
@Slf4j
public class FirebaseConfig {

    @Value("${firebase.api.key:}")
    private String firebaseApiKey;

    @Value("${firebase.service-account.path:}")
    private String serviceAccountPath;

    @Value("${FIREBASE_CREDENTIALS_JSON:}")
    private String rawCredentialsJson;

    @Value("${firebase.project-id}")
    private String projectId;

    @Value("${firebase.http.connect-timeout-ms}")
    private int connectTimeoutMs;

    @Value("${firebase.http.response-timeout-seconds}")
    private int responseTimeoutSeconds;

    @Value("${firebase.http.read-timeout-seconds}")
    private int readTimeoutSeconds;

    // UTC clock shared by the application.
    @Bean
    @Primary
    public Clock clock() {
        Clock clock = Clock.systemUTC();
        log.info("System Clock initialized at {}", clock.instant());
        return clock;
    }

    // Firebase Admin SDK initialization.
    @Bean
    public FirebaseApp firebaseApp(Clock clock) throws IOException {
        Instant start = clock.instant();

        log.info("Initializing Firebase App at {}", start);

        if (projectId == null || projectId.isBlank()) {
            throw new IllegalStateException(
                    "Firebase project ID is missing. Configure firebase.project-id.");
        }

        // Avoid initializing the default Firebase app twice.
        for (FirebaseApp existingApp : FirebaseApp.getApps()) {
            if (FirebaseApp.DEFAULT_APP_NAME.equals(existingApp.getName())) {
                log.info(
                        "Reusing existing Firebase app for project: {}",
                        existingApp.getOptions().getProjectId()
                );
                return existingApp;
            }
        }

        GoogleCredentials credentials = loadServiceAccountCredentials();

        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(credentials)
                .setProjectId(projectId)
                .build();

        FirebaseApp app = FirebaseApp.initializeApp(options);

        log.info("Firebase app initialized for project: {}", projectId);
        return app;
    }

    /**
     * Loads Firebase credentials from either a filesystem path or a raw environment JSON string.
     * Prioritizes filesystem path if configured and reachable; falls back to raw env string.
     */
    private GoogleCredentials loadServiceAccountCredentials() throws IOException {
        InputStream inputStream = null;

        // Strategy A: Attempt to load from a physical filesystem path
        if (serviceAccountPath != null && !serviceAccountPath.isBlank()) {
            Path credentialsPath = Path.of(serviceAccountPath).toAbsolutePath().normalize();
            if (Files.isRegularFile(credentialsPath) && Files.isReadable(credentialsPath)) {
                log.info("Loading Firebase service-account credentials from filesystem path: {}", credentialsPath);
                inputStream = Files.newInputStream(credentialsPath);
            } else {
                log.warn("Configured path is missing or unreadable: {}. Attempting environment fallback...", credentialsPath);
            }
        }

        // Strategy B: Fall back to raw string stream parsing if filesystem check failed
        if (inputStream == null && rawCredentialsJson != null && !rawCredentialsJson.isBlank()) {
            log.info("Loading Firebase service-account credentials directly from FIREBASE_CREDENTIALS_JSON environment variable.");
            inputStream = new ByteArrayInputStream(rawCredentialsJson.getBytes(StandardCharsets.UTF_8));
        }

        // If neither strategy yielded an active stream, reject context startup
        if (inputStream == null) {
            throw new IllegalStateException(
                    "Firebase credentials missing! Provide a valid file path in 'firebase.service-account.path' "
                            + "or populate the 'FIREBASE_CREDENTIALS_JSON' environment variable."
            );
        }

        try (InputStream managedStream = inputStream) {
            GoogleCredentials credentials = GoogleCredentials.fromStream(managedStream);

            // Retain the explicit scopes used in the existing configuration.
            return credentials.createScoped(Arrays.asList(
                    "https://www.googleapis.com/auth/firebase",
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/datastore"
            ));
        }
    }

    // Firestore.
    @Bean
    @Primary
    public Firestore firestore(FirebaseApp app) {
        Firestore firestore = FirestoreClient.getFirestore(app);
        log.info("Firestore created from Firebase app");
        return firestore;
    }

    // Firebase Authentication.
    @Bean
    public FirebaseAuth firebaseAuth(FirebaseApp firebaseApp, Clock clock) {
        FirebaseAuth auth = FirebaseAuth.getInstance(firebaseApp);
        log.info("Firebase Auth initialized at {}", clock.instant());
        return auth;
    }

    // Shared reactive HTTP client.
    @Bean
    public HttpClient httpClient(Clock clock) {
        Instant now = clock.instant();

        HttpClient client = HttpClient.create()
                .option(
                        ChannelOption.CONNECT_TIMEOUT_MILLIS,
                        connectTimeoutMs
                )
                .responseTimeout(
                        Duration.ofSeconds(responseTimeoutSeconds)
                )
                .doOnConnected(connection ->
                        connection.addHandlerLast(
                                new ReadTimeoutHandler(readTimeoutSeconds)
                        )
                )
                .doOnRequest((request, connection) ->
                        log.debug(
                                "HTTP request initiated at {}: {} {}",
                                clock.instant(),
                                request.method(),
                                request.uri()
                        )
                )
                .doOnResponse((response, connection) ->
                        log.debug(
                                "HTTP response received at {}: Status {}",
                                clock.instant(),
                                response.status()
                        )
                );

        log.info(
                "HTTP Client configured at {} - Connect: {}ms, "
                        + "Response: {}s, Read: {}s",
                now,
                connectTimeoutMs,
                responseTimeoutSeconds,
                readTimeoutSeconds
        );

        return client;
    }

    // Firebase health indicator.
    @Bean
    public FirebaseHealthIndicator firebaseHealthIndicator(
            FirebaseApp firebaseApp,
            Firestore firestore,
            Clock clock
    ) {
        return new FirebaseHealthIndicator(firebaseApp, firestore, clock);
    }

    public static class FirebaseHealthIndicator {

        private final FirebaseApp firebaseApp;
        private final Firestore firestore;
        private final Clock clock;

        public FirebaseHealthIndicator(
                FirebaseApp firebaseApp,
                Firestore firestore,
                Clock clock
        ) {
            this.firebaseApp = firebaseApp;
            this.firestore = firestore;
            this.clock = clock;
        }

        public boolean isHealthy() {
            Instant checkTime = clock.instant();

            try {
                if (firebaseApp == null || firebaseApp.getOptions() == null) {
                    log.error("Firebase app not initialized at {}", checkTime);
                    return false;
                }
                if (firestore == null) {
                    log.error("Firestore instance missing from health indicator lookup at {}", checkTime);
                    return false;
                }
                return true;
            } catch (Exception e) {
                log.error("Firebase health check exception at {}: {}", checkTime, e.getMessage());
                return false;
            }
        }
    }
}
