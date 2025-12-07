package com.techStack.authSys.service.authentication;

import com.google.cloud.Timestamp;
import com.techStack.authSys.dto.AuthResult;
import com.techStack.authSys.models.Roles;
import com.techStack.authSys.models.TokenPair;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.JwtService;
import com.techStack.authSys.repository.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * Generates JWT tokens and persists session data.
 * Handles token creation, session management, and AuthResult construction.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenGenerationService {

    private final JwtService jwtService;
    private final RateLimiterService.SessionService sessionService;

    /**
     * Main method for generating tokens with full AuthResult response
     */
    public Mono<AuthResult> generateAndPersistTokens(
            User user,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            Set<String> permissions
    ) {
        Instant issuedAt = Instant.now();
        String sessionId = generateSessionId();

        // Use JwtService's generateTokenPairWithExpiry to get tokens + expiry times
        return jwtService.generateTokenPairWithExpiry(user, ipAddress, userAgent, permissions)
                .flatMap(components -> {
                    // Extract tokens and expiry times from components
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
                        log.info("Generated tokens for user: {} with session: {}",
                                user.getEmail(), sessionId))
                .doOnError(e ->
                        log.error("Failed to generate tokens for user: {}", user.getEmail(), e));
    }

    /**
     * Generates a unique session identifier.
     */
    private String generateSessionId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Persists session data in the database.
     */
    private Mono<Void> persistSession(
            User user,
            String sessionId,
            String ipAddress,
            String deviceFingerprint,
            TokenPair tokens,
            Instant issuedAt,
            Instant refreshExpiry,
            Instant accessTokenExpiry) {

        // Calculate the Firestore expiry timestamp
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
                .doOnSuccess(v -> log.debug("Session persisted: {}", sessionId))
                .doOnError(e -> log.error("Failed to persist session: {}", sessionId, e));
    }

    /**
     * Builds the final AuthResult response object.
     */
    private AuthResult buildAuthResult(
            User user,
            String sessionId,
            TokenPair tokens,
            Instant issuedAt,
            Instant refreshExpiry) {

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
}