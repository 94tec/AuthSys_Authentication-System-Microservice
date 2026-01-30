package com.techStack.authSys.service.registration;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

import static com.techStack.authSys.constants.SecurityConstants.COLLECTION_REGISTRATION_METADATA;
import static com.techStack.authSys.constants.SecurityConstants.COLLECTION_USERS;

/**
 * Registration Metadata Service
 *
 * Manages registration metadata persistence for audit trails.
 * Stores when, where, and how users registered.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationMetadataService {

    private final Firestore firestore;
    private final Clock clock;

    /**
     * Save registration metadata to Firestore
     */
    public Mono<Void> saveRegistrationMetadata(
            User user,
            String ipAddress,
            String deviceFingerprint
    ) {
        // Input validation
        if (user == null || user.getId() == null || ipAddress == null || ipAddress.isBlank()) {
            log.warn("Invalid input: User or IP address is null/empty");
            return Mono.error(new IllegalArgumentException(
                    "User or IP address cannot be null/empty"));
        }

        Instant now = clock.instant();

        Map<String, Object> metadata = Map.of(
                "userId", user.getId(),
                "email", user.getEmail(),
                "ipAddress", ipAddress,
                "deviceFingerprint", deviceFingerprint != null ? deviceFingerprint : "",
                "registeredAt", now,
                "status", user.getStatus().name(),
                "roles", user.getRoleNames() != null ? user.getRoleNames() : "",
                "userAgent", user.getLastLoginUserAgent() != null ? user.getLastLoginUserAgent() : ""
        );

        ApiFuture<DocumentReference> apiFuture = firestore
                .collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_REGISTRATION_METADATA)
                .add(metadata);

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(apiFuture))
                .doOnSuccess(v -> log.debug("✅ Saved registration metadata for user: {}",
                        user.getId()))
                .doOnError(e -> log.error("❌ Failed to save metadata for user: {}",
                        user.getId(), e))
                .onErrorResume(e -> {
                    log.error("Non-fatal error saving metadata: {}", e.getMessage());
                    return Mono.empty(); // Non-fatal - don't break registration flow
                })
                .then();
    }
}