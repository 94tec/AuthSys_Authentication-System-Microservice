package com.techStack.authSys.config.intergration;

import com.google.auth.oauth2.AccessToken;
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

import java.io.IOException;
import java.io.InputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Firebase Configuration
 *
 * Configures Firebase App, Auth, and Firestore.
 * Provides Clock bean for timestamp operations.
 */
@Getter
@Configuration
@Slf4j
public class FirebaseConfig {

    /* =========================
       Configuration Properties
       ========================= */

    @Value("${firebase.api.key}")
    private String firebaseApiKey;

    @Value("${firebase.service-account.path}")
    private String serviceAccountPath;

    @Value("${firebase.project-id}")
    private String projectId;

    @Value("${firebase.http.connect-timeout-ms}")
    private int connectTimeoutMs;

    @Value("${firebase.http.response-timeout-seconds}")
    private int responseTimeoutSeconds;

    @Value("${firebase.http.read-timeout-seconds}")
    private int readTimeoutSeconds;

    /* =========================
       Clock Configuration
       ========================= */

    /**
     * System Clock bean for production use
     * Returns UTC time
     */
    @Bean
    @Primary
    public Clock clock() {
        Clock systemClock = Clock.systemUTC();
        Instant now = systemClock.instant();

        log.info("System Clock initialized at {}", now);
        return systemClock;
    }

    /* =========================
       Firebase App Configuration
       ========================= */

    /**
     * Firebase App initialization
     */
    @Bean
    public FirebaseApp firebaseApp(Clock clock) throws IOException {
        Instant startTime = clock.instant();

        try {
            log.info("Initializing Firebase App at {}", startTime);

            InputStream serviceAccount = loadServiceAccount();
            GoogleCredentials credentials = GoogleCredentials.fromStream(serviceAccount);

            FirebaseOptions options = FirebaseOptions.builder()
                    .setCredentials(credentials)
                    .setProjectId(projectId)
                    .build();

            log.info("Firebase configuration - Project ID: {}", options.getProjectId());

            FirebaseApp app;
            if (FirebaseApp.getApps().isEmpty()) {
                app = FirebaseApp.initializeApp(options);

                Instant endTime = clock.instant();
                Duration initDuration = Duration.between(startTime, endTime);

                log.info("Firebase application initialized successfully at {} (duration: {})",
                        endTime, initDuration);
            } else {
                app = FirebaseApp.getInstance();
                log.info("Using existing Firebase application instance");
            }

            return app;

        } catch (IOException e) {
            Instant failTime = clock.instant();
            Duration failDuration = Duration.between(startTime, failTime);

            log.error("Firebase initialization failed at {} (duration: {}): {}",
                    failTime, failDuration, e.getMessage(), e);
            throw new RuntimeException("Failed to initialize Firebase", e);
        }
    }

    /**
     * Load service account credentials
     */
    private InputStream loadServiceAccount() {
        InputStream serviceAccount = getClass()
                .getClassLoader()
                .getResourceAsStream(serviceAccountPath);

        if (serviceAccount == null) {
            log.error("Firebase service account file not found: {}", serviceAccountPath);
            throw new IllegalStateException(
                    "Firebase service account file not found in classpath: " + serviceAccountPath);
        }

        log.debug("Loaded service account from: {}", serviceAccountPath);
        return serviceAccount;
    }

    /* =========================
       Firebase Services
       ========================= */

    /**
     * Firebase Auth instance
     */
    @Bean
    public FirebaseAuth firebaseAuth(FirebaseApp firebaseApp, Clock clock) {
        Instant now = clock.instant();

        FirebaseAuth auth = FirebaseAuth.getInstance(firebaseApp);
        log.info("Firebase Auth initialized at {}", now);

        return auth;
    }

    /**
     * Firestore instance
     */
    @Primary
    @Bean
    public Firestore firestore(FirebaseApp firebaseApp, Clock clock) {
        Instant now = clock.instant();

        Firestore firestore = FirestoreClient.getFirestore(firebaseApp);
        log.info("Firestore initialized for project {} at {}", projectId, now);

        return firestore;
    }

    /* =========================
       HTTP Client Configuration
       ========================= */

    /**
     * Configured HTTP client with timeouts
     */
    @Bean
    public HttpClient httpClient(Clock clock) {
        Instant now = clock.instant();

        HttpClient client = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMs)
                .responseTimeout(Duration.ofSeconds(responseTimeoutSeconds))
                .doOnConnected(conn ->
                        conn.addHandlerLast(new ReadTimeoutHandler(readTimeoutSeconds)))
                .doOnRequest((req, conn) ->
                        log.debug("HTTP request initiated at {}: {} {}",
                                clock.instant(), req.method(), req.uri()))
                .doOnResponse((res, conn) ->
                        log.debug("HTTP response received at {}: Status {}",
                                clock.instant(), res.status()));

        log.info("HTTP Client configured at {} - Connect timeout: {}ms, Response timeout: {}s, Read timeout: {}s",
                now, connectTimeoutMs, responseTimeoutSeconds, readTimeoutSeconds);

        return client;
    }

    /* =========================
       Credential Management
       ========================= */

    /**
     * Firebase Credentials Adapter
     *
     * Provides scoped credentials for Firebase services
     */
    public static class FirebaseCredentialsAdapter extends GoogleCredentials {

        private final GoogleCredentials credentials;
        private final Clock clock;

        /**
         * Default constructor (for backward compatibility)
         */
        public FirebaseCredentialsAdapter() throws IOException {
            this(Clock.systemUTC());
        }

        /**
         * Constructor with Clock injection
         */
        public FirebaseCredentialsAdapter(Clock clock) throws IOException {
            this.clock = clock;
            Instant now = clock.instant();

            log.debug("Initializing Firebase credentials at {}", now);

            this.credentials = GoogleCredentials.getApplicationDefault()
                    .createScoped(Arrays.asList(
                            "https://www.googleapis.com/auth/firebase",
                            "https://www.googleapis.com/auth/cloud-platform"
                    ));

            log.info("Firebase credentials initialized with scopes at {}", now);
        }

        @Override
        public AccessToken refreshAccessToken() throws IOException {
            Instant refreshStart = clock.instant();

            try {
                log.debug("Refreshing Firebase access token at {}", refreshStart);

                AccessToken token = credentials.refreshAccessToken();

                Instant refreshEnd = clock.instant();
                Duration refreshDuration = Duration.between(refreshStart, refreshEnd);

                log.info("Access token refreshed successfully at {} (duration: {})",
                        refreshEnd, refreshDuration);

                if (token.getExpirationTime() != null) {
                    log.debug("New token expires at: {}",
                            Instant.ofEpochMilli(token.getExpirationTime().getTime()));
                }

                return token;

            } catch (IOException e) {
                Instant failTime = clock.instant();
                Duration failDuration = Duration.between(refreshStart, failTime);

                log.error("Failed to refresh access token at {} (duration: {}): {}",
                        failTime, failDuration, e.getMessage());
                throw e;
            }
        }

        /**
         * Get token expiration time
         */
        public Instant getTokenExpiration() throws IOException {
            AccessToken token = refreshAccessToken();
            if (token.getExpirationTime() != null) {
                return Instant.ofEpochMilli(token.getExpirationTime().getTime());
            }
            return null;
        }

        /**
         * Check if token is expired
         */
        public boolean isTokenExpired() throws IOException {
            Instant expiration = getTokenExpiration();
            if (expiration == null) {
                return true;
            }

            Instant now = clock.instant();
            boolean expired = now.isAfter(expiration);

            if (expired) {
                log.warn("Firebase token expired at {} (checked at {})", expiration, now);
            }

            return expired;
        }
    }

    /* =========================
       Health Check
       ========================= */

    /**
     * Check Firebase connectivity
     */
    @Bean
    public FirebaseHealthIndicator firebaseHealthIndicator(
            FirebaseApp firebaseApp,
            Firestore firestore,
            Clock clock
    ) {
        return new FirebaseHealthIndicator(firebaseApp, firestore, clock);
    }

    /**
     * Firebase Health Indicator
     */
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

        /**
         * Check if Firebase is healthy
         */
        public boolean isHealthy() {
            Instant checkTime = clock.instant();

            try {
                // Check if Firebase app is initialized
                if (firebaseApp == null || firebaseApp.getOptions() == null) {
                    log.error("Firebase app not initialized at {}", checkTime);
                    return false;
                }

                // Check if Firestore is accessible
                if (firestore == null) {
                    log.error("Firestore not accessible at {}", checkTime);
                    return false;
                }

                log.debug("Firebase health check passed at {}", checkTime);
                return true;

            } catch (Exception e) {
                log.error("Firebase health check failed at {}: {}", checkTime, e.getMessage());
                return false;
            }
        }

        /**
         * Get Firebase status information
         */
        public Map<String, Object> getStatus() {
            Instant statusTime = clock.instant();

            Map<String, Object> status = new HashMap<>();
            status.put("timestamp", statusTime.toString());
            status.put("healthy", isHealthy());
            status.put("projectId", firebaseApp.getOptions().getProjectId());
            status.put("appName", firebaseApp.getName());

            return status;
        }
    }
}