package com.techStack.authSys.service.token;

import com.google.cloud.Timestamp;
import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.models.auth.SessionContext;
import com.techStack.authSys.models.auth.TokenComponentsWithExpiry;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.models.authorization.Permissions;
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
 * <p>Improvements over previous version:
 * <ul>
 *   <li>{@link SessionContext} — replaces the 8-parameter {@code persistSession} signature.
 *       All session-related fields travel together as a typed value object, making call
 *       sites readable and preventing argument-order mistakes.</li>
 *   <li>{@link #generateAndPersistTokens} pipeline — the {@code flatMap} lambda no longer
 *       does extraction, persistence, and result-building inline. Each concern is a named
 *       method call in a linear chain.</li>
 *   <li>{@link #toFirestoreTimestamp} — the {@code Timestamp.of(Date.from(instant))} double
 *       conversion is extracted once so it can't drift between callers.</li>
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenGenerationService {

    private final JwtService jwtService;
    private final SessionService sessionService;
    private final Clock clock;

    /* =========================
       Token Generation
       ========================= */

    /**
     * Generate JWT token pair, persist the session, and return a complete {@link AuthResult}.
     *
     * <p>Pipeline:
     * <ol>
     *   <li>Generate access + refresh tokens with expiry metadata.</li>
     *   <li>Bundle everything into a {@link SessionContext} value object.</li>
     *   <li>Persist the session — fail fast if this fails (no silent swallow).</li>
     *   <li>Build and return the {@link AuthResult}.</li>
     * </ol>
     */
    public Mono<AuthResult> generateAndPersistTokens(
            User user,
            String ipAddress,
            String deviceFingerprint,
            String userAgent,
            Set<Permissions> permissions
    ) {
        Instant issuedAt  = clock.instant();
        String sessionId  = UUID.randomUUID().toString();

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

    /* =========================
       Session Context Assembly
       ========================= */

    /**
     * Bundle all session-relevant fields into a {@link SessionContext}.
     *
     * <p>Previously the {@code flatMap} lambda extracted {@link TokenPair} and expiry instants
     * inline before passing eight separate arguments to {@link #persistSession}. Assembling
     * the context here gives the rest of the pipeline a single, typed object to thread through.
     */
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
                .tokens(new TokenPair(components.getAccessToken(), components.getRefreshToken()))
                .issuedAt(issuedAt)
                .accessExpiry(components.getAccessTokenExpiry())
                .refreshExpiry(components.getRefreshTokenExpiry())
                .build();
    }

    /* =========================
       Session Persistence
       ========================= */

    /**
     * Persist the session record in the database.
     *
     * <p>Accepts a {@link SessionContext} instead of eight individual parameters.
     * The previous signature was {@code persistSession(User, String, String, String,
     * TokenPair, Instant, Instant, Instant)} — eight arguments of mostly the same type
     * ({@link Instant} × 3, {@link String} × 4) with no compiler protection against
     * transposing {@code accessExpiry} and {@code refreshExpiry}.
     */
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
                .doOnSuccess(__ -> log.debug("Session persisted: {} at {}", ctx.getSessionId(), ctx.getIssuedAt()))
                .doOnError(e  -> log.error("Failed to persist session: {}", ctx.getSessionId(), e));
    }

    /* =========================
       AuthResult Building
       ========================= */

    /**
     * Construct the {@link AuthResult} returned to the caller.
     *
     * <p>Accepts {@link SessionContext} so no expiry/token fields need to be
     * re-extracted from a separate scope.
     */
    private AuthResult buildAuthResult(User user, SessionContext ctx) {
        List<Roles>       roleList        = new ArrayList<>(user.getRoles());
        List<Permissions> permissionsList = new ArrayList<>(user.getAllPermissions());

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

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Convert a Java {@link Instant} to a Firestore {@link Timestamp}.
     *
     * <p>The previous code inlined {@code Timestamp.of(java.util.Date.from(instant))}
     * directly in {@code persistSession}. Extracting it here makes the conversion
     * testable and prevents the two-step chain from being re-typed elsewhere.
     */
    private static Timestamp toFirestoreTimestamp(Instant instant) {
        return Timestamp.of(Date.from(instant));
    }
}