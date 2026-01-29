package com.techStack.authSys.service.registration;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Manages registration metadata persistence.
 * Stores audit trail of registration events.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationMetadataService {

    private static final String COLLECTION_USERS = "users";
    private static final String COLLECTION_REGISTRATION_METADATA = "registration_metadata";

    private final Firestore firestore;

    /**
     * Saves registration metadata to Firestore.
     * This creates an audit trail of when and where users registered.
     */
    public Mono<Void> saveRegistrationMetadata(User user, String ipAddress) {
        // Input validation
        if (user == null || user.getId() == null || ipAddress == null || ipAddress.isBlank()) {
            log.warn("Invalid input: User or IP address is null/empty");
            return Mono.error(new IllegalArgumentException(
                    "User or IP address cannot be null/empty"));
        }

        UserDTO.RegistrationMetadata metadata = new UserDTO.RegistrationMetadata(
                user.getId(),
                ipAddress,
                Instant.now(),
                user.getDeviceFingerprint()
        );

        ApiFuture<DocumentReference> apiFuture = firestore.collection(COLLECTION_USERS)
                .document(user.getId())
                .collection(COLLECTION_REGISTRATION_METADATA)
                .add(metadata);

        CompletableFuture<DocumentReference> completableFuture =
                FirestoreUtil.toCompletableFuture(apiFuture);

        return Mono.fromFuture(completableFuture)
                .doOnSuccess(v -> log.debug("✅ Saved registration metadata for user: {}",
                        user.getId()))
                .doOnError(e -> log.error("❌ Failed to save metadata for user: {}",
                        user.getId(), e))
                .onErrorResume(e -> {
                    if (e instanceof ExecutionException) {
                        log.error("Firestore execution error: {}", e.getMessage());
                    } else {
                        log.error("Unexpected error saving metadata: {}", e.getMessage());
                    }
                    // Non-fatal: Don't break registration flow
                    return Mono.empty();
                })
                .then();
    }
}
