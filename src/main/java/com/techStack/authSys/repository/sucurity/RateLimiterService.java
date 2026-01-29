package com.techStack.authSys.repository.sucurity;

import com.google.cloud.Timestamp;
import com.techStack.authSys.dto.internal.SessionRecord;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;

public interface RateLimiterService {
    Mono<Void> checkAuthRateLimit(String ipAddress, String email);
    Mono<Boolean> recordFailedAttempt(String email, String ipAddress);

    Mono<Object> checkThreatApiRateLimit(String ipAddress);

    interface SessionService {

        Mono<Void> createSession(String userId, String sessionId, String ipAddress, String deviceFingerprint,
                                 String accessToken, String refreshToken, Instant lastActivity, Timestamp firestoreExpiresAt,
                                 Instant accessTokenExpiry, Instant refreshTokenExpiry);

        Mono<Void> invalidateSession(Object userId, String ipAddress);

        Mono<Void> invalidateUserSessions(String userId);

        Mono<Void> invalidateAllSessionsForUser(Object userId);

        Mono<Boolean> validateSession(String userId, String accessToken);

        Flux<SessionRecord> getActiveSessionsCached(String userId);

        Mono<List<SessionRecord>> fetchActiveSessionsFromFirestore(String userId);

        Mono<Void> updateSessionTokens(String userId, String newAccessToken,
                                       String newRefreshToken, String ipAddress);
        Mono<Void> recordSessionActivity(String sessionId);
        Mono<Void> cleanupAfterBlacklistRemoval(String encryptedIp);
    }
}