package com.techStack.authSys.controller.user;

import com.techStack.authSys.dto.request.ForcePasswordChangeRequest;
import com.techStack.authSys.dto.request.PasswordChangeRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.security.context.CurrentUserProvider;
import com.techStack.authSys.service.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Password Change Controller
 *
 * Handles password change operations.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class PasswordChangeController {

    /* =========================
       Dependencies
       ========================= */

    private final UserService userService;
    private final CurrentUserProvider currentUserProvider;
    private final Clock clock;

    /* =========================
       Password Change Operations
       ========================= */

    /**
     * Change password for current user
     */
    @PostMapping("/change-password")
    public Mono<ResponseEntity<ApiResponse>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            ServerWebExchange exchange) {

        Instant startTime = clock.instant();

        return currentUserProvider.getCurrentUserId()
                .doOnNext(userId -> log.info("Password change request at {} for user: {}",
                        startTime, userId))
                .flatMap(userId -> userService.changePassword(
                        userId,
                        request.getCurrentPassword(),
                        request.getNewPassword()
                ))
                .then(Mono.fromRunnable(() ->
                        exchange.getSession().subscribe(WebSession::invalidate)
                ))
                .then(Mono.fromCallable(() -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.info("✅ Password changed successfully at {} in {}", endTime, duration);

                    return ResponseEntity.ok(new ApiResponse(
                            true,
                            "Password changed successfully",
                            null
                    ));
                }))
                .onErrorResume(CustomException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Password change failed at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity.status(e.getStatus())
                            .body(new ApiResponse(
                                    false,
                                    e.getMessage(),
                                    null
                            )));
                });
    }

    /**
     * Force password change for a user (admin only)
     */
    @PostMapping("/force-change-password")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN', 'ADMIN')")
    public Mono<ResponseEntity<ApiResponse>> forceChangePassword(
            @Valid @RequestBody ForcePasswordChangeRequest request) {

        Instant changeTime = clock.instant();

        log.warn("🔐 Force password change at {} for user: {}",
                changeTime, request.getUserId());

        return userService.forcePasswordChange(request.getUserId(), request.getNewPassword())
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Password forcefully changed at {} for user: {}",
                            completionTime, request.getUserId());

                    return ResponseEntity.ok(new ApiResponse(
                            true,
                            "Password changed successfully",
                            null
                    ));
                }))
                .onErrorResume(CustomException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Force password change failed at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.just(ResponseEntity.status(e.getStatus())
                            .body(new ApiResponse(
                                    false,
                                    e.getMessage(),
                                    null
                            )));
                });
    }
}