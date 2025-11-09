package com.techStack.authSys.controller;

import com.techStack.authSys.dto.*;
import com.techStack.authSys.exception.AuthException;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.exception.EmailAlreadyVerifiedException;
import com.techStack.authSys.models.Permissions;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.AuthServiceController;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.repository.RateLimiterService;
import com.techStack.authSys.service.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

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

    private final EmailServiceInstance1 emailService;
    private final AuditLogService auditLogService;
    private final AuthService authService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RateLimiterService.SessionService sessionService;
    private final JwtService jwtService;
    private final AuthServiceController authServiceController;
    private final DeviceVerificationService deviceVerificationService;
    private final PermissionProvider permissionProvider;

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
     * Check if email is available
     *
     * @param email Email to check
     * @return Mono with availability status
     */
    @GetMapping("/check-email")
    public Mono<ResponseEntity<ApiResponse<Boolean>>> checkEmailAvailability(
            @RequestParam String email) {

        return firebaseServiceAuth.checkEmailAvailability(email)
                .map(available -> {
                    ApiResponse<Boolean> response = new ApiResponse<>(
                            true,
                            available ? "Email is available" : "Email is already registered",
                            available
                    );
                    return ResponseEntity.ok(response);
                });
    }

    /**
     * Resend verification email
     *
     * @param email User email
     * @return Mono with success response
     */
    @PostMapping("/resend-verification")
    public Mono<ResponseEntity<ApiResponse<Void>>> resendVerificationEmail(
            @RequestParam String email,
            ServerWebExchange exchange) {

        //String ipAddress = extractClientIp(exchange);
        String ipAddress = deviceVerificationService.extractClientIp(exchange);

        return authService.resendVerificationEmail(email, ipAddress)
                .then(Mono.fromCallable(() -> {
                    ApiResponse<Void> response = new ApiResponse<>(
                            true,
                            "Verification email sent successfully. Please check your inbox.",
                            null
                    );
                    return ResponseEntity.ok(response);
                }));
    }

    @GetMapping("/verify-email")
    public Mono<ResponseEntity<String>> verifyEmail(
            @RequestParam("token") String token,
            @RequestHeader(value = "X-Forwarded-For", required = false) String forwardedIp,
            ServerHttpRequest request) {

        // Extract client IP
        String clientIp = Optional.ofNullable(forwardedIp)
                .map(ip -> ip.split(",")[0].trim())
                .orElseGet(() -> {
                    InetSocketAddress remoteAddress = request.getRemoteAddress();
                    return (remoteAddress != null) ? remoteAddress.getAddress().getHostAddress() : "UNKNOWN";
                });

        logger.info("📧 Processing email verification for token (first 10 chars): {}...",
                token.length() > 10 ? token.substring(0, 10) : token);

        // Just let exceptions bubble up - GlobalExceptionHandler will catch them
        return authService.verifyEmail(token, clientIp)
                .then(Mono.just(ResponseEntity.ok("Email verified successfully. You can now log in.")))
                .doOnSuccess(__ -> logger.info("✅ Email verification completed successfully"));
    }

    @PostMapping("/logout")
    public Mono<ResponseEntity<Object>> logout(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            WebRequest request) {

        String ipAddress = getClientIp(request);
        String token = extractToken(authHeader);

        return jwtService.getUserIdFromToken(token)
                .flatMap(userId -> sessionService.invalidateSession(userId, ipAddress)
                        .then(jwtService.validateToken(token, "access"))
                        .thenReturn(ResponseEntity.ok().build()))
                .doOnSuccess(response -> log.info("User logged out successfully"))
                .doOnError(e -> log.error("Logout failed: {}", e.getMessage()));
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            ServerWebExchange exchange) {

        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(ipAddress, userAgent);

        return authServiceController.authenticate(
                        loginRequest.getEmail(),
                        loginRequest.getPassword(),
                        ipAddress,
                        deviceFingerprint,
                        userAgent,
                        Instant.now().toString(),
                        loginRequest.getUserId()
                )
                .flatMap(authResult -> {
                    if (!authResult.getUser().isEmailVerified()) {
                        return emailService.sendVerificationEmail(authResult.getUser().getId(), ipAddress)
                                .thenReturn(
                                        ResponseEntity.status(HttpStatus.FORBIDDEN)
                                                .body(AuthResponse.builder()
                                                        .warning("Email not verified. Verification email resent")
                                                        .build())
                                );
                    }
                    return handleLoginSuccess(authResult, ipAddress, deviceFingerprint, userAgent);
                })
                .doOnSuccess(res -> logger.info("✅ Successful login for {}", loginRequest.getEmail()))
                .onErrorResume(AuthException.class, e -> {
                    logger.warn("⚠️ Login failed for {}: {} - Status: {}",
                            loginRequest.getEmail(), e.getMessage(), e.getStatus());

                    auditLogService.logAuthFailure(loginRequest.getEmail(), ipAddress, deviceFingerprint, e.getMessage());

                    return Mono.just(ResponseEntity
                            .status(e.getStatus())
                            .body(AuthResponse.builder()
                                    .message("Authentication failed")
                                    .warning(e.getMessage()) // This will now be user-friendly
                                    .timestamp(new Date())
                                    .build()));
                })
                .onErrorResume(e -> {
                    logger.error("❌ Unexpected login error for {}: {}", loginRequest.getEmail(), e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(AuthResponse.builder()
                                    .message("Login error")
                                    .warning("An unexpected error occurred. Please try again.")
                                    .timestamp(new Date())
                                    .build()));
                });
    }
    private Mono<ResponseEntity<AuthResponse>> handleLoginSuccess(AuthResult authResult, String ipAddress, String deviceFingerprint, String userAgent) {
        AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
                .userId(authResult.getUser().getId())
                .email(authResult.getUser().getEmail())
                .firstName(authResult.getUser().getFirstName())
                .lastName(authResult.getUser().getLastName())
                //.MfaRequired(authResult.getUser().isMfaRequired())
                .profileImageUrl(authResult.getUser().getProfilePictureUrl())
                .build();

        List<String> resolved = permissionProvider.resolveEffectivePermission(authResult.getUser()).stream().toList();
        List<Permissions> permissions = permissionProvider.deserializePermissions(resolved);

        AuthResponse response = AuthResponse.builder()
                .accessToken(authResult.getAccessToken())
                .refreshToken(authResult.getRefreshToken())
                .accessTokenExpiry(authResult.getAccessTokenExpiry())
                .refreshTokenExpiry(authResult.getRefreshTokenExpiry())
                .user(userInfo)
                .permissions(permissions)
                .build();

        return Mono.just(ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, response.getAccessToken())
                .body(response));
    }

    private String getClientIp(WebRequest request) {
        if (request instanceof ServletWebRequest servletWebRequest) {
            HttpServletRequest servletRequest = servletWebRequest.getRequest();
            return servletRequest.getRemoteAddr(); // ✅ Correctly extracts IP address
        }
        return "UNKNOWN";
    }

    private String extractToken(String authHeader) {
        return authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
    }

    @PostMapping("/resend-email-verification")
    public Mono<ResponseEntity<Object>> resendVerificationEmail(
            @RequestParam String userId,
            @RequestHeader("X-Forwarded-For") String ipAddress) {

        return emailService.sendVerificationEmail(userId, ipAddress)
                .thenReturn(ResponseEntity.ok().build())
                .onErrorResume(e -> {
                    if (e instanceof EmailAlreadyVerifiedException) {
                        return Mono.just(ResponseEntity.status(HttpStatus.CONFLICT).build());
                    }
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build());
                });
    }

}
