package com.techStack.authSys.service.auth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.user.PermissionData;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserFactory;
import com.techStack.authSys.models.user.UserStatus;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.authorization.PermissionService;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

/**
 * Google Authentication Service Implementation
 *
 * Handles Google OAuth authentication and account linking.
 * Uses refactored services for user creation and permission management.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleAuthServiceImpl implements GoogleAuthService {

    // ✅ REFACTORED DEPENDENCIES
    private final FirestoreUserRepository userRepository;
    private final PermissionService permissionService;
    private final RoleAssignmentService roleAssignmentService;
    private final MetricsService metricsService;
    private final Clock clock;

    @Value("${google.oauth.client-id}")
    private String googleClientId;

    private static final String OAUTH_PROVIDER = "GOOGLE";
    private static final String OAUTH_ATTRIBUTE_PROVIDER = "oauth_provider";
    private static final String OAUTH_ATTRIBUTE_PROVIDER_ID = "oauth_provider_id";
    private static final String OAUTH_ATTRIBUTE_PICTURE = "oauth_picture";

    @Override
    public Mono<User> authenticateWithGoogle(String idToken, String ipAddress, String deviceFingerprint) {
        Instant startTime = clock.instant();
        log.info("Google authentication attempt at {} from IP: {}", startTime, ipAddress);

        return verifyGoogleToken(idToken)
                .flatMap(payload -> processGoogleAuthentication(payload, ipAddress, deviceFingerprint, startTime))
                .doOnSuccess(user -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);
                    log.info("✅ Google authentication successful at {} in {} for: {}",
                            endTime, duration, HelperUtils.maskEmail(user.getEmail()));
                    metricsService.incrementCounter("auth.google.success");
                    metricsService.recordTimer("auth.google.duration", duration);
                })
                .doOnError(e -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);
                    log.error("❌ Google authentication failed at {} after {}: {}", endTime, duration, e.getMessage());
                    metricsService.incrementCounter("auth.google.failure");
                })
                .onErrorMap(e -> (e instanceof CustomException) ? e :
                        new CustomException(HttpStatus.UNAUTHORIZED, "Google authentication failed: " + e.getMessage()));
    }

    @Override
    public Mono<Payload> verifyGoogleToken(String idToken) {
        Instant verifyTime = clock.instant();
        log.debug("Verifying Google token at {}", verifyTime);

        return Mono.fromCallable(() -> {
            try {
                FirebaseToken firebaseToken = FirebaseAuth.getInstance().verifyIdToken(idToken);
                Payload payload = new Payload();
                payload.setEmail(firebaseToken.getEmail());
                payload.setEmailVerified(firebaseToken.isEmailVerified());
                payload.set("name", firebaseToken.getName());
                payload.set("picture", firebaseToken.getPicture());
                payload.setSubject(firebaseToken.getUid());
                log.debug("✅ Google token verified at {} for: {}", clock.instant(),
                        HelperUtils.maskEmail(firebaseToken.getEmail()));
                return payload;
            } catch (FirebaseAuthException e) {
                log.error("❌ Google token verification failed at {}: {}", clock.instant(), e.getMessage());
                throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid Google ID token: " + e.getMessage());
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<User> linkGoogleAccount(String userId, String idToken) {
        Instant linkTime = clock.instant();
        log.info("Linking Google account at {} for user: {}", linkTime, userId);

        return verifyGoogleToken(idToken)
                .flatMap(payload -> userRepository.findById(userId)
                        .flatMap(user -> {
                            String providerId = payload.getSubject();
                            String picture = payload.get("picture") != null ? payload.get("picture").toString() : "";

                            user.getAttributes().put(OAUTH_ATTRIBUTE_PROVIDER, OAUTH_PROVIDER);
                            user.getAttributes().put(OAUTH_ATTRIBUTE_PROVIDER_ID, providerId);
                            user.getAttributes().put(OAUTH_ATTRIBUTE_PICTURE, picture);
                            user.setUpdatedAt(clock.instant());

                            return userRepository.save(user);
                        }))
                .doOnSuccess(user -> {
                    log.info("✅ Google account linked at {} for user: {}", clock.instant(), userId);
                    metricsService.incrementCounter("user.google.linked");
                })
                .doOnError(e -> {
                    log.error("❌ Failed to link Google account at {} for user {}: {}",
                            clock.instant(), userId, e.getMessage());
                    metricsService.incrementCounter("user.google.link.failure");
                });
    }

    @Override
    public Mono<User> unlinkGoogleAccount(String userId) {
        Instant unlinkTime = clock.instant();
        log.info("Unlinking Google account at {} for user: {}", unlinkTime, userId);

        return userRepository.findById(userId)
                .flatMap(user -> {
                    user.getAttributes().remove(OAUTH_ATTRIBUTE_PROVIDER);
                    user.getAttributes().remove(OAUTH_ATTRIBUTE_PROVIDER_ID);
                    user.getAttributes().remove(OAUTH_ATTRIBUTE_PICTURE);
                    user.setUpdatedAt(clock.instant());

                    return userRepository.save(user);
                })
                .doOnSuccess(user -> {
                    log.info("✅ Google account unlinked at {} for user: {}", clock.instant(), userId);
                    metricsService.incrementCounter("user.google.unlinked");
                })
                .doOnError(e -> {
                    log.error("❌ Failed to unlink Google account at {} for user {}: {}",
                            clock.instant(), userId, e.getMessage());
                    metricsService.incrementCounter("user.google.unlink.failure");
                });
    }

    @Override
    public Mono<Boolean> hasGoogleAccountLinked(String userId) {
        return userRepository.findById(userId)
                .map(user -> user.getAttributes().containsKey(OAUTH_ATTRIBUTE_PROVIDER) &&
                        OAUTH_PROVIDER.equals(user.getAttributes().get(OAUTH_ATTRIBUTE_PROVIDER)))
                .defaultIfEmpty(false);
    }

    @Override
    public Mono<Map<String, String>> getGoogleOAuthInfo(String userId) {
        return userRepository.findById(userId)
                .map(user -> Map.of(
                        "provider", user.getAttributes().getOrDefault(OAUTH_ATTRIBUTE_PROVIDER, "").toString(),
                        "providerId", user.getAttributes().getOrDefault(OAUTH_ATTRIBUTE_PROVIDER_ID, "").toString(),
                        "picture", user.getAttributes().getOrDefault(OAUTH_ATTRIBUTE_PICTURE, "").toString()
                ))
                .defaultIfEmpty(Map.of());
    }

    /* =========================
       Private Helpers
       ========================= */

    /**
     * Process Google authentication - handle existing or create new user
     */
    private Mono<User> processGoogleAuthentication(Payload payload, String ipAddress,
                                                   String deviceFingerprint, Instant startTime) {
        String email = payload.getEmail();
        String providerId = payload.getSubject();
        log.info("Processing Google authentication for: {} at {}", HelperUtils.maskEmail(email), clock.instant());

        return userRepository.findByEmail(email)
                .flatMap(existingUser -> handleExistingUser(existingUser, payload, providerId))
                .switchIfEmpty(Mono.defer(() -> createNewGoogleUser(payload, providerId, ipAddress, deviceFingerprint)))
                .flatMap(user -> updateLastLogin(user, ipAddress));
    }

    /**
     * Handle existing user Google login
     */
    private Mono<User> handleExistingUser(User existingUser, Payload payload, String providerId) {
        Instant now = clock.instant();
        log.info("Existing user found for Google login at {}: {}", now, HelperUtils.maskEmail(existingUser.getEmail()));

        // Link Google account if not already linked
        if (!existingUser.getAttributes().containsKey(OAUTH_ATTRIBUTE_PROVIDER)) {
            String picture = payload.get("picture") != null ? payload.get("picture").toString() : "";

            existingUser.getAttributes().put(OAUTH_ATTRIBUTE_PROVIDER, OAUTH_PROVIDER);
            existingUser.getAttributes().put(OAUTH_ATTRIBUTE_PROVIDER_ID, providerId);
            existingUser.getAttributes().put(OAUTH_ATTRIBUTE_PICTURE, picture);
            existingUser.setUpdatedAt(now);

            log.info("✅ Linking Google account for existing user: {}", HelperUtils.maskEmail(existingUser.getEmail()));
            return userRepository.save(existingUser);
        }

        return Mono.just(existingUser);
    }

    /**
     * Create new user from Google OAuth
     * ✅ REFACTORED: Uses UserFactory and atomic save
     */
    private Mono<User> createNewGoogleUser(Payload payload, String providerId,
                                           String ipAddress, String deviceFingerprint) {
        String email = payload.getEmail();
        String name = payload.get("name") != null ? payload.get("name").toString() : "";
        String picture = payload.get("picture") != null ? payload.get("picture").toString() : "";

        log.info("Creating new user from Google OAuth: {}", HelperUtils.maskEmail(email));

        // Build user using UserFactory
        User newUser = UserFactory.createOAuthUser(
                email,
                name,
                OAUTH_PROVIDER,
                providerId,
                String.valueOf(clock.instant())
        );

        // Add Google-specific attributes
        newUser.getAttributes().put(OAUTH_ATTRIBUTE_PICTURE, picture);
        newUser.setEmailVerified(payload.getEmailVerified());
        newUser.setDeviceFingerprint(deviceFingerprint);

        // Prepare permissions
        Set<String> permissions = permissionService.resolveEffectivePermissions(newUser);

        PermissionData permData = PermissionData.builder()
                .roles(new ArrayList<>(newUser.getRoleNames()))
                .permissions(new ArrayList<>(permissions))
                .status(UserStatus.ACTIVE)
                .approvedBy("GOOGLE_OAUTH")
                .approvedAt(clock.instant())
                .build();

        // ✅ REFACTORED: Use atomic save
        return userRepository.saveUserAtomic(newUser, ipAddress, deviceFingerprint, permData)
                .doOnSuccess(user -> {
                    log.info("✅ New Google OAuth user created: {}", HelperUtils.maskEmail(user.getEmail()));
                    metricsService.incrementCounter("user.google.created");
                })
                .doOnError(e -> {
                    log.error("❌ Failed to create Google OAuth user: {}", e.getMessage());
                    metricsService.incrementCounter("user.google.creation.failure");
                });
    }

    /**
     * Update last login timestamp
     */
    private Mono<User> updateLastLogin(User user, String ipAddress) {
        return userRepository.updateLastLogin(user.getId(), ipAddress)
                .thenReturn(user);
    }
}
