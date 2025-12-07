package com.techStack.authSys.service.authentication;

import com.techStack.authSys.service.JwtService;
import com.techStack.authSys.repository.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Handles user logout operations.
 * Invalidates sessions and revokes tokens.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LogoutService {

    private final JwtService jwtService;
    private final RateLimiterService.SessionService sessionService;

    /**
     * Logs out a user by invalidating their session and token.
     *
     * @param token JWT access token
     * @param ipAddress Client IP address
     * @return Mono<Void> on successful logout
     */
    public Mono<Void> logout(String token, String ipAddress) {
        return jwtService.getUserIdFromToken(token)
                .flatMap(userId -> invalidateUserSession(userId, ipAddress, token))
                .doOnSuccess(v -> log.info("✅ User logged out successfully from IP: {}", ipAddress))
                .doOnError(e -> log.error("❌ Logout failed for IP {}: {}", ipAddress, e.getMessage()));
    }

    /**
     * Invalidates user session and validates token before revocation.
     */
    private Mono<Void> invalidateUserSession(String userId, String ipAddress, String token) {
        return sessionService.invalidateSession(userId, ipAddress)
                .then(jwtService.validateToken(token, "access"))
                .doOnSuccess(v -> log.debug("Session invalidated for user: {}", userId))
                .then();
    }
}
