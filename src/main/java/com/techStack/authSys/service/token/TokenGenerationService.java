package com.techStack.authSys.service.token;

import com.google.cloud.Timestamp;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.models.auth.SessionContext;
import com.techStack.authSys.models.auth.TokenComponentsWithExpiry;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.models.user.Roles;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.session.SessionService;
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
 *
 * Migration note — v1 → v2:
 *   generateAndPersistTokens() previously accepted Set<Permissions>.
 *   Now accepts Set<String> — permission full names e.g. "portfolio:publish".
 *
 *   buildAuthResult() previously built List<Permissions> permissionsList
 *   via new ArrayList<>(user.getAllPermissions()) — this didn't compile since
 *   getAllPermissions() returns Set<String> not Set<Permissions>.
 *   Fixed to List<String>.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenGenerationService {

    private final JwtService jwtService;
    private final SessionService sessionService;
    private final Clock clock;

    // -------------------------------------------------------------------------
    // Token Generation
    // -------------------------------------------------------------------------

    /**
     * Generate JWT token pair, persist the session, and return a complete AuthResult.
     *
     * Fix from original: parameter was Set<Permissions>. Now Set<String>.
     *
     * @param user              the authenticated user
     * @param ipAddress         client IP address
     * @param deviceFingerprint client device fingerprint
     * @param userAgent         client user agent string
     * @param permissions       resolved effective permission full name strings
     * @return Mono emitting the complete AuthResult
     */
    public Mono<AuthResult> generateAndPersistTokens(
            User user,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            List<String> permissions
    ) {
        Instant issuedAt = clock.instant();
        String sessionId = UUID.randomUUID().toString();

        log.debug("Generating tokens for user: {} at {}", user.getEmail(), issuedAt);

        return jwtService.generateTokenPairWithExpiry(user, ipAddress, userAgent, permissions)
                .map(components -> buildSessionContext(
                        user, sessionId, ipAddress, deviceFingerprint, issuedAt, components))
                .flatMap(ctx -> persistSession(ctx).thenReturn(ctx))
                .map(ctx -> buildAuthResult(user, ctx))
                .doOnSuccess(result -> log.info(
                        "Tokens generated for user: {} session: {} at {}",
                        user.getEmail(), sessionId, issuedAt))
                .doOnError(e -> log.error(
                        "Failed to generate tokens for user: {}", user.getEmail(), e));
    }

    // -------------------------------------------------------------------------
    // Session Context Assembly
    // -------------------------------------------------------------------------

    private SessionContext buildSessionContext(
            User user,
            String sessionId,
            String ipAddress,
            String deviceFingerprint,
            Instant issuedAt,
            TokenComponentsWithExpiry components
    ) {
        return SessionContext.builder()
                .userId(user.getId())
                .sessionId(sessionId)
                .ipAddress(ipAddress)
                .deviceFingerprint(deviceFingerprint)
                .tokens(new TokenPair(
                        components.getAccessToken(), components.getRefreshToken()))
                .issuedAt(issuedAt)
                .accessExpiry(components.getAccessTokenExpiry())
                .refreshExpiry(components.getRefreshTokenExpiry())
                .build();
    }

    // -------------------------------------------------------------------------
    // Session Persistence
    // -------------------------------------------------------------------------

    private Mono<Void> persistSession(SessionContext ctx) {
        return sessionService.createSession(
                        ctx.getUserId(),
                        ctx.getSessionId(),
                        ctx.getIpAddress(),
                        ctx.getDeviceFingerprint(),
                        ctx.getTokens().getAccessToken(),
                        ctx.getTokens().getRefreshToken(),
                        ctx.getIssuedAt(),
                        toFirestoreTimestamp(ctx.getRefreshExpiry()),
                        ctx.getAccessExpiry(),
                        ctx.getRefreshExpiry()
                )
                .doOnSuccess(__ -> log.debug(
                        "Session persisted: {} at {}", ctx.getSessionId(), ctx.getIssuedAt()))
                .doOnError(e -> log.error(
                        "Failed to persist session: {}", ctx.getSessionId(), e));
    }

    // -------------------------------------------------------------------------
    // AuthResult Building
    // -------------------------------------------------------------------------

    /**
     * Construct the AuthResult returned to the caller.
     *
     * Fix from original:
     *   List<Permissions> permissionsList = new ArrayList<>(user.getAllPermissions())
     *   didn't compile — getAllPermissions() returns Set<String>, not Set<Permissions>.
     *   Changed to List<String>.
     *
     *   List<Roles> roleList is fine — user.getRoles() returns Set<Roles>.
     */
    private AuthResult buildAuthResult(User user, SessionContext ctx) {
        List<Roles>  roleList        = new ArrayList<>(user.getRoles());
        List<String> permissionsList = new ArrayList<>(user.getAllPermissions());

        return new AuthResult(
                user,
                user.getId(),
                ctx.getSessionId(),
                ctx.getTokens().getAccessToken(),
                ctx.getTokens().getRefreshToken(),
                ctx.getIssuedAt(),
                ctx.getRefreshExpiry(),
                roleList,
                permissionsList,
                user.isMfaRequired(),
                user.getLoginAttempts(),
                ctx.getIssuedAt()
        );
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private static Timestamp toFirestoreTimestamp(Instant instant) {
        return Timestamp.of(Date.from(instant));
    }
}