package com.techStack.authSys.controller.user;

import com.techStack.authSys.dto.response.UserProfileDTO;
import com.techStack.authSys.service.user.UserProfileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * User Profile Controller
 *
 * Handles user profile CRUD operations.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/user-profiles")
@RequiredArgsConstructor
public class UserProfileController {

    /* =========================
       Dependencies
       ========================= */

    private final UserProfileService userProfileService;
    private final Clock clock;

    /* =========================
       Profile Operations
       ========================= */

    /**
     * Create user profile
     */
    @PostMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:create') or #userId == authentication.principal.id")
    public Mono<ResponseEntity<Map<String, Object>>> createUserProfile(
            @PathVariable UUID userId,
            @RequestBody UserProfileDTO profileDTO) {

        Instant createTime = clock.instant();

        log.info("Create profile request at {} for user: {}", createTime, userId);

        return userProfileService.createUserProfile(userId, profileDTO)
                .map(profile -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Profile created at {} for user: {}", completionTime, userId);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "Profile created successfully",
                            "data", profile,
                            "timestamp", completionTime.toString()
                    ));
                });
    }

    /**
     * Get user profile by user ID
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:read') or #userId == authentication.principal.id")
    public Mono<ResponseEntity<Map<String, Object>>> getUserProfile(@PathVariable UUID userId) {
        Instant requestTime = clock.instant();

        log.debug("Get profile request at {} for user: {}", requestTime, userId);

        return userProfileService.getUserProfile(userId)
                .map(profile -> ResponseEntity.ok(Map.of(
                        "success", true,
                        "data", profile,
                        "timestamp", requestTime.toString()
                )))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    /**
     * Update user profile
     */
    @PutMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:update') or #userId == authentication.principal.id")
    public Mono<ResponseEntity<Map<String, Object>>> updateUserProfile(
            @PathVariable UUID userId,
            @RequestBody UserProfileDTO profileDTO) {

        Instant updateTime = clock.instant();

        log.info("Update profile request at {} for user: {}", updateTime, userId);

        return userProfileService.updateUserProfile(userId, profileDTO)
                .map(profile -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Profile updated at {} for user: {}", completionTime, userId);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "Profile updated successfully",
                            "data", profile,
                            "timestamp", completionTime.toString()
                    ));
                })
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    /**
     * Delete user profile
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('profile:delete') or #userId == authentication.principal.id")
    public Mono<ResponseEntity<Map<String, Object>>> deleteUserProfile(@PathVariable UUID userId) {
        Instant deleteTime = clock.instant();

        log.warn("Delete profile request at {} for user: {}", deleteTime, userId);

        return userProfileService.deleteUserProfile(userId)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Profile deleted at {} for user: {}", completionTime, userId);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "Profile deleted successfully",
                            "timestamp", completionTime.toString()
                    ));
                }));
    }
}