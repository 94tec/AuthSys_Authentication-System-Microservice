package com.techStack.authSys.models.auth;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Session Context
 *
 * Immutable value object carrying all fields required to persist a user session
 * and build an {@link com.techStack.authSys.dto.internal.AuthResult}.
 *
 * <p>Introduced to replace the 8-parameter
 * {@code persistSession(User, String, String, String, TokenPair, Instant, Instant, Instant)}
 * signature in {@code TokenGenerationService}. The previous signature had three {@link Instant}
 * parameters and four {@link String} parameters in a row — no compiler protection against
 * transposing {@code accessExpiry} and {@code refreshExpiry}, or {@code ipAddress} and
 * {@code deviceFingerprint}.
 *
 * <p>Usage:
 * <pre>{@code
 * SessionContext ctx = SessionContext.builder()
 *     .userId(user.getId())
 *     .sessionId(sessionId)
 *     .ipAddress(ipAddress)
 *     .deviceFingerprint(deviceFingerprint)
 *     .tokens(tokenPair)
 *     .issuedAt(issuedAt)
 *     .accessExpiry(accessExpiry)
 *     .refreshExpiry(refreshExpiry)
 *     .build();
 * }</pre>
 */
@Getter
@Builder
public class SessionContext {

    /** Internal user identifier. */
    private final String userId;

    /** Unique identifier for this session (UUID). */
    private final String sessionId;

    /** Client IP address at the time of authentication. */
    private final String ipAddress;

    /** Device fingerprint provided by the client. */
    private final String deviceFingerprint;

    /** The generated access + refresh token pair. */
    private final TokenPair tokens;

    /** Timestamp at which the tokens were issued. */
    private final Instant issuedAt;

    /** Expiry timestamp of the access token. */
    private final Instant accessExpiry;

    /** Expiry timestamp of the refresh token. */
    private final Instant refreshExpiry;
}