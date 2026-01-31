package com.techStack.authSys.service.token;

import com.google.cloud.Timestamp;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.sucurity.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Token Generation Service
 *
 * Generates JWT tokens and persists session data.
 * Handles token creation, session management, and AuthResult construction.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenGenerationService {

    private final JwtService jwtService;
    private final RateLimiterService.SessionService sessionService;
    private final Clock clock;

    /* =========================
       Token Generation
       ========================= */

    /**
     * Generate and persist tokens with full AuthResult response
     */
    public Mono<AuthResult> generateAndPersistTokens(
            User user,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            Set<String> permissions
    ) {
        Instant issuedAt = clock.instant();
        String sessionId = generateSessionId();

        log.debug("Generating tokens for user: {} at {}", user.getEmail(), issuedAt);

        return jwtService.generateTokenPairWithExpiry(user, ipAddress, userAgent, permissions)
                .flatMap(components -> {
                    // Extract tokens and expiry times
                    TokenPair tokens = new TokenPair(
                            components.getAccessToken(),
                            components.getRefreshToken()
                    );
                    Instant accessExpiry = components.getAccessTokenExpiry();
                    Instant refreshExpiry = components.getRefreshTokenExpiry();

                    // Persist session to database
                    return persistSession(
                            user,
                            sessionId,
                            ipAddress,
                            deviceFingerprint,
                            tokens,
                            issuedAt,
                            refreshExpiry,
                            accessExpiry
                    ).thenReturn(
                            buildAuthResult(
                                    user,
                                    sessionId,
                                    tokens,
                                    issuedAt,
                                    refreshExpiry
                            )
                    );
                })
                .doOnSuccess(authResult ->
                        log.info("Generated tokens for user: {} with session: {} at {}",
                                user.getEmail(), sessionId, issuedAt))
                .doOnError(e ->
                        log.error("Failed to generate tokens for user: {}", user.getEmail(), e));
    }

    /* =========================
       Session Persistence
       ========================= */

    /**
     * Persist session data in database
     */
    private Mono<Void> persistSession(
            User user,
            String sessionId,
            String ipAddress,
            String deviceFingerprint,
            TokenPair tokens,
            Instant issuedAt,
            Instant refreshExpiry,
            Instant accessTokenExpiry
    ) {
        // Convert Instant to Firestore Timestamp
        Timestamp firestoreExpiresAt = Timestamp.of(java.util.Date.from(refreshExpiry));

        return sessionService.createSession(
                        user.getId(),
                        sessionId,
                        ipAddress,
                        deviceFingerprint,
                        tokens.getAccessToken(),
                        tokens.getRefreshToken(),
                        issuedAt,
                        firestoreExpiresAt,
                        accessTokenExpiry,
                        refreshExpiry
                )
                .doOnSuccess(v -> log.debug("Session persisted: {} at {}", sessionId, issuedAt))
                .doOnError(e -> log.error("Failed to persist session: {}", sessionId, e));
    }

    /* =========================
       AuthResult Building
       ========================= */

    /**
     * Build the final AuthResult response object
     */
    private AuthResult buildAuthResult(
            User user,
            String sessionId,
            TokenPair tokens,
            Instant issuedAt,
            Instant refreshExpiry
    ) {
        List<Roles> roleList = new ArrayList<>(user.getRoles());

        return new AuthResult(
                user,
                user.getId(),
                sessionId,
                tokens.getAccessToken(),
                tokens.getRefreshToken(),
                issuedAt,
                refreshExpiry,
                roleList,
                user.isMfaRequired(),
                user.getLoginAttempts(),
                issuedAt
        );
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Generate a unique session identifier
     */
    private String generateSessionId() {
        return UUID.randomUUID().toString();
    }
}