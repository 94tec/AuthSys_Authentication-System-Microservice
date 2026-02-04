package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.*;
import com.techStack.authSys.util.validation.HelperUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Authentication Controller
 *
 * Handles user registration and authentication endpoints.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    /* =========================
       Dependencies
       ========================= */

    private final AuthService authService;
    private final AuthenticationOrchestrator authenticationOrchestrator;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final DeviceVerificationService deviceVerificationService;
    private final LogoutService logoutService;
    private final LoginResponseBuilder loginResponseBuilder;
    private final Clock clock;

    /* =========================
       User Registration
       ========================= */

    /**
     * Register a new user
     */
    @PostMapping("/register")
    public Mono<ResponseEntity<ApiResponse<User>>> registerUser(
            @Valid @RequestBody UserRegistrationDTO userDto,
            ServerWebExchange exchange) {

        Instant startTime = clock.instant();

        log.info("Registration request at {} for email: {}",
                startTime, HelperUtils.maskEmail(userDto.getEmail()));

        return authService.registerUser(userDto, exchange)
                .map(user -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.info("✅ Registration completed at {} in {} for user: {}",
                            endTime, duration, user.getId());

                    ApiResponse<User> response = new ApiResponse<>(
                            true,
                            "Registration successful! Please check your email to verify your account.",
                            user
                    );
                    return ResponseEntity
                            .status(HttpStatus.CREATED)
                            .body(response);
                });

        // Error handling delegated to GlobalExceptionHandler
    }

    /* =========================
       Email Verification
       ========================= */

    /**
     * Resend verification email
     */
    @PostMapping("/resend-verification")
    public Mono<ResponseEntity<ApiResponse<Void>>> resendVerificationEmail(
            @RequestParam String email,
            ServerWebExchange exchange) {

        Instant requestTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);

        log.info("Resend verification request at {} for: {} from IP: {}",
                requestTime, HelperUtils.maskEmail(email), ipAddress);

        return authService.resendVerificationEmail(email, ipAddress)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Verification email sent at {} to: {}",
                            completionTime, HelperUtils.maskEmail(email));

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Verification email sent successfully. Please check your inbox.",
                            null
                    ));
                }));

        // Error handling delegated to GlobalExceptionHandler
    }

    /**
     * Verify email address using token
     */
    @GetMapping("/verify-email")
    public Mono<ResponseEntity<ApiResponse<Object>>> verifyEmail(
            @RequestParam("token") String token,
            ServerWebExchange exchange) {

        Instant verificationTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);

        log.info("Email verification attempt at {} from IP: {}", verificationTime, ipAddress);

        return authService.verifyEmail(token, ipAddress)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Email verification successful at {}", completionTime);

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Email verified successfully. You can now log in.",
                            null
                    ));
                }));

        // Error handling delegated to GlobalExceptionHandler
    }

    /* =========================
       User Login
       ========================= */

    /**
     * Authenticate user and return tokens
     */
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            ServerWebExchange exchange) {

        Instant loginTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress, userAgent);

        log.info("Login attempt at {} for: {} from IP: {}",
                loginTime, HelperUtils.maskEmail(loginRequest.getEmail()), ipAddress);

        return authenticationOrchestrator.authenticate(
                        loginRequest.getEmail(),
                        loginRequest.getPassword(),
                        ipAddress,
                        deviceFingerprint,
                        userAgent,
                        null
                )
                .flatMap(authResult -> handleLoginResult(
                        authResult,
                        loginRequest.getEmail(),
                        ipAddress,
                        deviceFingerprint
                ))
                .doOnSuccess(res -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(loginTime, completionTime);

                    log.info("✅ Login successful at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(loginRequest.getEmail()));
                });

        // Error handling delegated to GlobalExceptionHandler
    }

    /* =========================
       User Logout
       ========================= */

    /**
     * Logout user and invalidate session
     */
    @PostMapping("/logout")
    public Mono<ResponseEntity<ApiResponse<Void>>> logout(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            WebRequest request) {

        Instant logoutTime = clock.instant();
        String ipAddress = extractClientIp(request);
        String token = extractToken(authHeader);

        log.info("Logout request at {} from IP: {}", logoutTime, ipAddress);

        return logoutService.logout(token, ipAddress)
                .then(Mono.fromCallable(() -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Logout successful at {}", completionTime);

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Logged out successfully",
                            null
                    ));
                }));

        // Error handling delegated to GlobalExceptionHandler
    }

    /* =========================
       Email Availability
       ========================= */

    /**
     * Check if email is available for registration
     */
    @GetMapping("/check-email")
    public Mono<ResponseEntity<ApiResponse<Boolean>>> checkEmailAvailability(
            @RequestParam String email) {

        Instant checkTime = clock.instant();

        log.debug("Email availability check at {} for: {}",
                checkTime, HelperUtils.maskEmail(email));

        return firebaseServiceAuth.checkEmailAvailability(email)
                .map(available -> ResponseEntity.ok(new ApiResponse<>(
                        true,
                        available ? "Email is available" : "Email is already registered",
                        available
                )));

        // Error handling delegated to GlobalExceptionHandler
    }

    /* =========================
       Private Helper Methods
       ========================= */

    /**
     * Handle successful login by checking email verification status
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
     * Handle login attempt with unverified email
     */
    private Mono<ResponseEntity<AuthResponse>> handleUnverifiedEmail(User user, String ipAddress) {
        Instant now = clock.instant();

        log.warn("Login attempt at {} with unverified email: {}",
                now, HelperUtils.maskEmail(user.getEmail()));

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
                    log.error("Failed to resend verification at {}: {}", now, e.getMessage());
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
     * Extract client IP from WebRequest
     */
    private String extractClientIp(WebRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return "UNKNOWN";
    }

    /**
     * Extract JWT token from Authorization header
     */
    private String extractToken(String authHeader) {
        return authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
    }
}