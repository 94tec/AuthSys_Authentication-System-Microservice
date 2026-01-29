package com.techStack.authSys.config.intergration;

import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.firestore.Firestore;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.cloud.FirestoreClient;
import io.netty.channel.ChannelOption;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import io.netty.handler.timeout.ReadTimeoutHandler;
import reactor.netty.http.client.HttpClient;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Arrays;

@Getter
@Configuration
public class FirebaseConfig {
    private static final Logger logger = LoggerFactory.getLogger(FirebaseConfig.class);

    @Value("${firebase.api.key}")
    private String firebaseApiKey;

    @Bean
    public FirebaseApp firebaseApp() throws IOException {
        try {
            InputStream serviceAccount = getClass().getClassLoader().getResourceAsStream("spring-data-a3ebb-firebase-adminsdk-fbsvc-2c7014e914.json");

            if (serviceAccount == null) {
                logger.error("Firebase service account file not found");
                throw new IllegalStateException("Firebase service account file not found in classpath");
            }

            FirebaseOptions options = FirebaseOptions.builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .setProjectId("spring-data-a3ebb")
                    .build();
            logger.info("Initializing Firebase for project: {}", options.getProjectId());

            if (FirebaseApp.getApps().isEmpty()) {
                FirebaseApp.initializeApp(options);
                logger.info("Firebase application initialized");
            }
            return FirebaseApp.getInstance();
        } catch (IOException e) {
            logger.error("Error initializing Firebase: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to initialize Firebase", e);
        }
    }
    @Bean
    public FirebaseAuth firebaseAuth(FirebaseApp firebaseApp) {
        return FirebaseAuth.getInstance(firebaseApp);
    }

    @Primary
    @Bean
    public Firestore firestore(FirebaseApp firebaseApp) {
        return FirestoreClient.getFirestore(firebaseApp);
    }

    @Bean
    public HttpClient httpClient() {
        return HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .responseTimeout(Duration.ofSeconds(5))
                .doOnConnected(conn ->
                        conn.addHandlerLast(new ReadTimeoutHandler(5)));
    }

    public class FirebaseCredentialsAdapter extends GoogleCredentials {
        private GoogleCredentials credentials;

        public FirebaseCredentialsAdapter() throws IOException {
            this.credentials = GoogleCredentials.getApplicationDefault()
                    .createScoped(Arrays.asList(
                            "https://www.googleapis.com/auth/firebase",
                            "https://www.googleapis.com/auth/cloud-platform"
                    ));
        }

        @Override
        public AccessToken refreshAccessToken() throws IOException {
            return credentials.refreshAccessToken();
        }
    }
}
