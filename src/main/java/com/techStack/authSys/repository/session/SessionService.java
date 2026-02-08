package com.techStack.authSys.repository.session;

import com.google.cloud.Timestamp;
import com.techStack.authSys.dto.internal.SessionRecord;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Session Service Interface
 *
 * Manages user sessions with Redis caching and Firestore persistence.
 *
 * ✅ FIXED: Single createSession method using Set<String> for device fingerprint
 */
public interface SessionService {

    /**
     * Create new session
     *
     * @param userId User ID
     * @param sessionId Session ID
     * @param ipAddress IP address
     * @param deviceFingerprint Device fingerprint (can be Set or converted from String)
     * @param accessToken Access token
     * @param refreshToken Refresh token
     * @param lastActivity Last activity timestamp
     * @param firestoreExpiresAt Firestore expiry timestamp
     * @param accessTokenExpiry Access token expiry
     * @param refreshTokenExpiry Refresh token expiry
     * @return Mono<Void> completing when session created
     */
    Mono<Void> createSession(
            String userId,
            String sessionId,
            String ipAddress,
            String deviceFingerprint,  // ✅ Use Set<String>
            String accessToken,
            String refreshToken,
            Instant lastActivity,
            Timestamp firestoreExpiresAt,
            Instant accessTokenExpiry,
            Instant refreshTokenExpiry
    );

    /**
     * Invalidate session by user ID and IP
     */
    Mono<Void> invalidateSession(Object userId, String ipAddress);

    /**
     * Invalidate user sessions in cache
     */
    Mono<Void> invalidateUserSessions(String userId);

    /**
     * Invalidate all sessions for user
     */
    Mono<Void> invalidateAllSessionsForUser(Object userId);

    /**
     * Validate session
     */
    Mono<Boolean> validateSession(String userId, String accessToken);

    /**
     * Get active sessions with caching
     */
    Flux<SessionRecord> getActiveSessionsCached(String userId);

    /**
     * Fetch active sessions from Firestore
     */
    Mono<List<SessionRecord>> fetchActiveSessionsFromFirestore(String userId);

    /**
     * Update session tokens
     */
    Mono<Void> updateSessionTokens(
            String userId,
            String newAccessToken,
            String newRefreshToken,
            String ipAddress
    );

    /**
     * Record session activity
     */
    Mono<Void> recordSessionActivity(String sessionId);

    /**
     * Cleanup sessions after blacklist removal
     */
    Mono<Void> cleanupAfterBlacklistRemoval(String encryptedIp);
}