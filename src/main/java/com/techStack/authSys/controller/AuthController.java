package com.techStack.authSys.controller;

import com.techStack.authSys.dto.*;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.*;
import com.techStack.authSys.service.authentication.AuthenticationOrchestrator;
import com.techStack.authSys.service.authentication.LoginResponseBuilder;
import com.techStack.authSys.service.authentication.LogoutService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.*;

/**
 * Authentication Controller
 * Handles user registration and authentication endpoints
 */

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final AuthenticationOrchestrator authenticationOrchestrator;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final DeviceVerificationService deviceVerificationService;
    private final LogoutService logoutService;
    private final LoginResponseBuilder loginResponseBuilder;

    // Register a new user
    @PostMapping("/register")
    public Mono<ResponseEntity<ApiResponse<User>>> registerUser(
            @Valid @RequestBody UserDTO userDto,
            ServerWebExchange exchange) {

        logger.info("Registration request received for email: {}",
                userDto.getEmail() != null ? userDto.getEmail().replaceAll("@.*", "@***") : "unknown");

        return authService.registerUser(userDto, exchange)
                .map(user -> {
                    ApiResponse<User> response = new ApiResponse<>(
                            true,
                            "Registration successful! Please check your email to verify your account.",
                            user
                    );
                    return ResponseEntity
                            .status(HttpStatus.CREATED)
                            .body(response);
                });

        // NOTE: Error handling is automatically done by GlobalExceptionHandler
        // No need for .onErrorResume() here - keeps controller clean
    }
    /**
     * Resend verification email.
     */
    @PostMapping("/resend-verification")
    public Mono<ResponseEntity<ApiResponse<Void>>> resendVerificationEmail(
            @RequestParam String email,
            ServerWebExchange exchange) {

        String ipAddress = deviceVerificationService.extractClientIp(exchange);

        return authService.resendVerificationEmail(email, ipAddress)
                .then(Mono.just(ResponseEntity.ok(new ApiResponse<>(
                        true,
                        "Verification email sent successfully. Please check your inbox.",
                        null
                ))));

        // Error handling delegated to GlobalExceptionHandler
    }

    /**
     * Verify email address using token.
     */
    @GetMapping("/verify-email")
    public Mono<ResponseEntity<ApiResponse<Object>>> verifyEmail(
            @RequestParam("token") String token,
            ServerWebExchange exchange) {

        String ipAddress = deviceVerificationService.extractClientIp(exchange);

        log.info("Email verification attempt from IP: {}", ipAddress);

        return authService.verifyEmail(token, ipAddress)
                .then(Mono.just(ResponseEntity.ok(new ApiResponse<>(
                        true,
                        "Email verified successfully. You can now log in.",
                        null
                ))))
                .doOnSuccess(__ -> log.info("✅ Email verification successful"));

        // Error handling delegated to GlobalExceptionHandler
    }
    //Authenticate user and return tokens.
    //Error handling follows the same pattern as registration.
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            ServerWebExchange exchange) {

        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress, userAgent);

        log.info("Login attempt for: {} from IP: {}", maskEmail(loginRequest.getEmail()), ipAddress);

        return authenticationOrchestrator.authenticate(
                        loginRequest.getEmail(),
                        loginRequest.getPassword(),
                        ipAddress,
                        deviceFingerprint,
                        userAgent,
                null
                )
                .flatMap(authResult -> handleLoginResult(authResult, loginRequest.getEmail(),
                        ipAddress, deviceFingerprint))
                .doOnSuccess(res -> log.info("✅ Login successful for: {}",
                        maskEmail(loginRequest.getEmail())));

        // Error handling delegated to GlobalExceptionHandler
        // No .onErrorResume() needed here - keeps controller clean!
    }

    /**
     * Logout user and invalidate session.
     */
    @PostMapping("/logout")
    public Mono<ResponseEntity<ApiResponse<Void>>> logout(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            WebRequest request) {

        String ipAddress = extractClientIp(request);
        String token = extractToken(authHeader);

        return logoutService.logout(token, ipAddress)
                .then(Mono.just(ResponseEntity.ok(new ApiResponse<>(
                        true,
                        "Logged out successfully",
                        null
                ))));

        // Error handling delegated to GlobalExceptionHandler
    }
    /**
     * Check if email is available for registration.
     */
    @GetMapping("/check-email")
    public Mono<ResponseEntity<ApiResponse<Boolean>>> checkEmailAvailability(
            @RequestParam String email) {

        return firebaseServiceAuth.checkEmailAvailability(email)
                .map(available -> ResponseEntity.ok(new ApiResponse<>(
                        true,
                        available ? "Email is available" : "Email is already registered",
                        available
                )));

        // Error handling delegated to GlobalExceptionHandler
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    /**
     * Handles successful login by checking email verification status.
     */
    private Mono<ResponseEntity<AuthResponse>> handleLoginResult(
            AuthResult authResult,
            String email,
            String ipAddress,
            String deviceFingerprint) {

        // Check if email is verified
        if (!authResult.getUser().isEmailVerified()) {
            return handleUnverifiedEmail(authResult.getUser(), ipAddress);
        }

        // Build success response
        return Mono.just(loginResponseBuilder.buildSuccessResponse(authResult));
    }

    /**
     * Handles login attempt with unverified email.
     */
    private Mono<ResponseEntity<AuthResponse>> handleUnverifiedEmail(User user, String ipAddress) {
        log.warn("Login attempt with unverified email: {}", maskEmail(user.getEmail()));

        return authService.resendVerificationEmail(user.getEmail(), ipAddress)
                .then(Mono.just(ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(AuthResponse.builder()
                                .success(false)
                                .message("Email not verified")
                                .warning("Please verify your email address before logging in. " +
                                        "A new verification link has been sent to your email.")
                                .build())
                ))
                .onErrorResume(e -> {
                    // If resend fails, still inform user about verification requirement
                    log.error("Failed to resend verification email: {}", e.getMessage());
                    return Mono.just(ResponseEntity
                            .status(HttpStatus.FORBIDDEN)
                            .body(AuthResponse.builder()
                                    .success(false)
                                    .message("Email not verified")
                                    .warning("Please verify your email address before logging in. " +
                                            "Check your inbox for the verification link.")
                                    .build())
                    );
                });
    }

    /**
     * Extracts client IP from WebRequest.
     */
    private String extractClientIp(WebRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return "UNKNOWN";
    }

    /**
     * Extracts JWT token from Authorization header.
     */
    private String extractToken(String authHeader) {
        return authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
    }

    /**
     * Masks email for logging (GDPR compliance).
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "unknown";
        }
        return email.replaceAll("@.*", "@***");
    }

}
