package com.techStack.authSys.repository.authorization;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.techStack.authSys.models.user.User;
import reactor.core.publisher.Mono;

import java.util.Set;  // ✅ ADDED

/**
 * Google Authentication Service
 */
public interface GoogleAuthService {

    /**
     * Authenticate user with Google ID token
     * ✅ FIXED: deviceFingerprint is now Set<String>
     */
    Mono<User> authenticateWithGoogle(
            String idToken,
            String ipAddress,
            String deviceFingerprint
    );

    /**
     * Verify Google ID token and return payload
     */
    Mono<Payload> verifyGoogleToken(String idToken);

    /**
     * Link Google account to existing user
     */
    Mono<User> linkGoogleAccount(String userId, String idToken);

    /**
     * Unlink Google account from user
     */
    Mono<User> unlinkGoogleAccount(String userId);

    /**
     * Check if user has Google account linked
     */
    Mono<Boolean> hasGoogleAccountLinked(String userId);

    /**
     * Get Google OAuth information for user
     */
    Mono<java.util.Map<String, String>> getGoogleOAuthInfo(String userId);
}