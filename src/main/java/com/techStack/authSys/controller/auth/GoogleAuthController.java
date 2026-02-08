package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.repository.authorization.GoogleAuthService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Google Authentication Controller
 *
 * Handles Google OAuth authentication.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class GoogleAuthController {

    /* =========================
       Dependencies
       ========================= */

    private final GoogleAuthService googleAuthService;
    private final DeviceVerificationService deviceVerificationService;
    private final Clock clock;

    /* =========================
       Google Sign-In
       ========================= */

    /**
     * Authenticate user with Google ID token
     */
    @PostMapping("/google-signin")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> googleSignIn(
            @RequestParam String idToken,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            ServerWebExchange exchange) {

        Instant startTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress, userAgent);

        log.info("Google sign-in attempt at {} from IP: {}", startTime, ipAddress);

        return googleAuthService.authenticateWithGoogle(idToken, ipAddress, deviceFingerprint)
                .map(user -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.info("✅ Google sign-in successful at {} in {} for user: {}",
                            endTime, duration, HelperUtils.maskEmail(user.getEmail()));

                    Map<String, Object> responseData = Map.of(
                            "userId", user.getId(),
                            "email", user.getEmail(),
                            "firstName", user.getFirstName(),
                            "lastName", user.getLastName(),
                            "emailVerified", user.isEmailVerified(),
                            "roles", user.getRoles(),
                            "authProvider", "GOOGLE",
                            "authenticatedAt", endTime.toString()
                    );

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google authentication successful",
                            responseData
                    ));
                })
                .onErrorResume(CustomException.class, e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(startTime, errorTime);

                    log.error("❌ Google sign-in failed at {} after {}: {}",
                            errorTime, duration, e.getMessage());

                    HttpStatus status = determineHttpStatus(e);

                    return Mono.just(ResponseEntity.status(status)
                            .body(new ApiResponse<>(
                                    false,
                                    e.getMessage(),
                                    Map.of(
                                            "errorType", e.getClass().getSimpleName(),
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(startTime, errorTime);

                    log.error("❌ Unexpected error during Google sign-in at {} after {}: {}",
                            errorTime, duration, e.getMessage(), e);

                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(new ApiResponse<>(
                                    false,
                                    "An unexpected error occurred during Google authentication",
                                    Map.of(
                                            "errorType", e.getClass().getSimpleName(),
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }

    /**
     * Verify Google ID token (for testing/validation)
     */
    @PostMapping("/google-verify")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> verifyGoogleToken(
            @RequestParam String idToken) {

        Instant verifyTime = clock.instant();

        log.debug("Google token verification at {}", verifyTime);

        return googleAuthService.verifyGoogleToken(idToken)
                .map(payload -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Google token verified at {} for email: {}",
                            completionTime, HelperUtils.maskEmail(payload.getEmail()));

                    Map<String, Object> tokenData = Map.of(
                            "email", payload.getEmail(),
                            "emailVerified", payload.getEmailVerified(),
                            "name", payload.get("name") != null ? payload.get("name") : "",
                            "picture", payload.get("picture") != null ? payload.get("picture") : "",
                            "verifiedAt", completionTime.toString()
                    );

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google token verified successfully",
                            tokenData
                    ));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Google token verification failed at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new ApiResponse<>(
                                    false,
                                    "Invalid Google token",
                                    Map.of(
                                            "errorType", e.getClass().getSimpleName(),
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }

    /**
     * Link Google account to existing user
     */
    @PostMapping("/google-link")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> linkGoogleAccount(
            @RequestParam String userId,
            @RequestParam String idToken) {

        Instant linkTime = clock.instant();

        log.info("Google account link request at {} for user: {}", linkTime, userId);

        return googleAuthService.linkGoogleAccount(userId, idToken)
                .map(user -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Google account linked at {} for user: {}",
                            completionTime, userId);

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google account linked successfully",
                            Map.<String, Object>of(
                                    "userId", user.getId(),
                                    "email", user.getEmail(),
                                    "googleLinked", true,
                                    "linkedAt", completionTime.toString()
                            )
                    ));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Google account linking failed at {} for user {}: {}",
                            errorTime, userId, e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    false,
                                    "Failed to link Google account: " + e.getMessage(),
                                    Map.<String, Object>of(
                                            "userId", userId,
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }


    /**
     * Unlink Google account from user
     */
    @PostMapping("/google-unlink")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> unlinkGoogleAccount(
            @RequestParam String userId) {

        Instant unlinkTime = clock.instant();

        log.info("Google account unlink request at {} for user: {}", unlinkTime, userId);

        return googleAuthService.unlinkGoogleAccount(userId)
                .map(user -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Google account unlinked at {} for user: {}",
                            completionTime, userId);

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google account unlinked successfully",
                            Map.<String, Object>of(
                                    "userId", user.getId(),
                                    "googleLinked", false,
                                    "unlinkedAt", completionTime.toString()
                            )
                    ));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Google account unlinking failed at {} for user {}: {}",
                            errorTime, userId, e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    false,
                                    "Failed to unlink Google account: " + e.getMessage(),
                                    Map.<String, Object>of(
                                            "userId", userId,
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }


    /* =========================
       Private Helper Methods
       ========================= */

    /**
     * Determine HTTP status from CustomException
     */
    private HttpStatus determineHttpStatus(CustomException e) {
        String message = e.getMessage().toLowerCase();

        if (message.contains("unauthorized") || message.contains("invalid token")) {
            return HttpStatus.UNAUTHORIZED;
        } else if (message.contains("bad request") || message.contains("invalid")) {
            return HttpStatus.BAD_REQUEST;
        } else if (message.contains("not found")) {
            return HttpStatus.NOT_FOUND;
        } else if (message.contains("conflict") || message.contains("already exists")) {
            return HttpStatus.CONFLICT;
        }

        // Check if CustomException has a status field
        if (e.getStatus() != null) {
            return e.getStatus();
        }

        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}