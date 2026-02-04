package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.internal.TokenValidationRequest;
import com.techStack.authSys.dto.request.PasswordResetRequest;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.service.user.PasswordResetService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

/**
 * Password Reset Controller
 *
 * Handles password reset workflows.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/password-reset")
@RequiredArgsConstructor
public class PasswordResetController {

    /* =========================
       Dependencies
       ========================= */

    private final PasswordResetService passwordResetService;
    private final Clock clock;

    /* =========================
       Password Reset Operations
       ========================= */

    /**
     * Initiate password reset
     */
    @PostMapping("/initiate")
    public Mono<ResponseEntity<Map<String, Object>>> initiatePasswordReset(
            @RequestBody PasswordResetRequest request) {

        Instant initiateTime = clock.instant();

        log.info("Password reset initiated at {} for email: {}",
                initiateTime, request.getEmail());

        return passwordResetService.initiatePasswordReset(request.getEmail())
                .map(token -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Password reset email sent at {}", completionTime);

                    return ResponseEntity.ok(Map.of(
                            "success", true,
                            "message", "Password reset email sent",
                            "timestamp", completionTime.toString()
                    ));
                })
                .onErrorResume(IllegalArgumentException.class, e -> {
                    log.warn("Invalid request at {}: {}", clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.badRequest().body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                })
                .onErrorResume(UserNotFoundException.class, e -> {
                    log.warn("User not found at {}: {}", clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                            "success", false,
                            "message", e.getMessage(),
                            "timestamp", clock.instant().toString()
                    )));
                })
                .onErrorResume(EmailSendingException.class, e -> {
                    log.error("Email sending failed at {}: {}", clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                            "success", false,
                            "message", "Failed to send reset email. Please try again later.",
                            "timestamp", clock.instant().toString()
                    )));
                })
                .onErrorResume(e -> {
                    log.error("Unexpected error at {}: {}", clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.internalServerError().body(Map.of(
                            "success", false,
                            "message", "An unexpected error occurred",
                            "timestamp", clock.instant().toString()
                    )));
                });
    }

    /**
     * Validate reset token
     */
    @PostMapping("/validate-token")
    public Mono<ResponseEntity<Map<String, Object>>> validateResetToken(
            @RequestBody TokenValidationRequest request) {

        Instant validationTime = clock.instant();

        log.debug("Token validation request at {}", validationTime);

        return passwordResetService.validateResetToken(request.getToken())
                .map(valid -> ResponseEntity.ok(Map.of(
                        "success", true,
                        "valid", valid,
                        "timestamp", validationTime.toString()
                )))
                .defaultIfEmpty(ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "valid", false,
                        "timestamp", validationTime.toString()
                )))
                .onErrorResume(e -> {
                    log.error("Token validation error at {}: {}",
                            clock.instant(), e.getMessage());
                    return Mono.just(ResponseEntity.internalServerError().body(Map.of(
                            "success", false,
                            "valid", false,
                            "timestamp", clock.instant().toString()
                    )));
                });
    }
}