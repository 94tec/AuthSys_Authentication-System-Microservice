package com.techStack.authSys.controller.admin;

import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.dto.response.UserDTO;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.AuthenticationOrchestrator;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.auth.LoginResponseBuilder;
import com.techStack.authSys.service.bootstrap.AdminUserManagementService;
import com.techStack.authSys.service.bootstrap.TransactionalBootstrapService;
import com.techStack.authSys.service.verification.EmailVerificationService;
import com.techStack.authSys.util.validation.HelperUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;

/**
 * Admin Authentication Controller
 *
 * Handles Super Admin and Admin user operations.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/super-admin")
@RequiredArgsConstructor
public class AdminAuthController {

    /* =========================
       Dependencies
       ========================= */

    // Authentication Services
    private final AuthenticationOrchestrator authenticationOrchestrator;
    private final LoginResponseBuilder loginResponseBuilder;

    // Admin Management Services
    private final TransactionalBootstrapService transactionalBootstrapService;
    private final AdminUserManagementService adminUserManagementService;

    // Support Services
    private final DeviceVerificationService deviceVerificationService;
    private final EmailVerificationService emailVerificationService;
    private final Clock clock;

    /* =========================
       Super Admin Registration
       ========================= */

    /**
     * Manually registers a Super Admin (for emergency situations)
     * Should be disabled in production or protected by additional security
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ResponseEntity<ApiResponse<Object>>> registerSuperAdmin(
            @RequestParam String email,
            @RequestParam String phone) {

        Instant startTime = clock.instant();

        log.warn("🚨 Manual Super Admin registration initiated at {} for: {}",
                startTime, HelperUtils.maskEmail(email));

        return transactionalBootstrapService.createSuperAdminTransactionally(email, phone)
                .then(Mono.fromCallable(() -> {
                    Instant endTime = clock.instant();

                    log.info("✅ Super Admin registration completed at {}", endTime);

                    return ResponseEntity
                            .status(HttpStatus.CREATED)
                            .body(new ApiResponse<>(
                                    true,
                                    "Super Admin created successfully. Check email for credentials.",
                                    null
                            ));
                }))
                .onErrorResume(e -> {
                    Instant endTime = clock.instant();

                    log.error("❌ Manual Super Admin registration failed at {}: {}",
                            endTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    false,
                                    e.getMessage(),
                                    null
                            ))
                    );
                });
    }

    /* =========================
       Admin Login
       ========================= */

    /**
     * Authenticate Super Admin or Admin users
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

        log.info("Admin login attempt at {} for: {} from IP: {}",
                loginTime, HelperUtils.maskEmail(loginRequest.getEmail()), ipAddress);

        // Determine permissions for admin login
        Set<String> permissions = getAdminPermissions();

        return authenticationOrchestrator.authenticate(
                        loginRequest.getEmail(),
                        loginRequest.getPassword(),
                        ipAddress,
                        deviceFingerprint,
                        userAgent,
                        permissions
                )
                .flatMap(authResult -> handleAdminLoginResult(authResult, ipAddress))
                .doOnSuccess(res -> {
                    Instant endTime = clock.instant();
                    log.info("✅ Admin login successful at {} for: {}",
                            endTime, HelperUtils.maskEmail(loginRequest.getEmail()));
                });

        // Error handling delegated to GlobalExceptionHandler
    }

    /* =========================
       Admin User Registration
       ========================= */

    /**
     * Register a new Admin user (Super Admin only)
     */
    @PostMapping("/register-admin")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<String>>> registerAdmin(
            @Valid @RequestBody UserDTO userDto,
            ServerWebExchange exchange) {

        Instant startTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress, userDto.getUserAgent());

        log.info("Admin registration by Super Admin at {} for: {}",
                startTime, HelperUtils.maskEmail(userDto.getEmail()));

        return adminUserManagementService.createAdminUser(userDto, exchange, ipAddress, deviceFingerprint)
                .map(user -> {
                    Instant endTime = clock.instant();

                    log.info("✅ Admin user created at {} - ID: {}", endTime, user.getId());

                    return ResponseEntity
                            .status(HttpStatus.CREATED)
                            .body(new ApiResponse<>(
                                    true,
                                    "Admin user created successfully. Credentials sent to email.",
                                    user.getId()
                            ));
                });

        // Error handling delegated to GlobalExceptionHandler
    }

    /* =========================
       Private Helper Methods
       ========================= */

    /**
     * Handle admin login result, checking email verification
     */
    private Mono<ResponseEntity<AuthResponse>> handleAdminLoginResult(
            AuthResult authResult,
            String ipAddress) {

        if (!authResult.getUser().isEmailVerified()) {
            return handleUnverifiedAdminEmail(authResult.getUser(), ipAddress);
        }

        return Mono.just(loginResponseBuilder.buildSuccessResponse(authResult));
    }

    /**
     * Handle login with unverified email
     */
    private Mono<ResponseEntity<AuthResponse>> handleUnverifiedAdminEmail(
            User user,
            String ipAddress) {

        Instant now = clock.instant();

        log.warn("Admin login attempt with unverified email at {}: {}",
                now, HelperUtils.maskEmail(user.getEmail()));

        return emailVerificationService.resendVerificationEmail(user.getEmail(), ipAddress)
                .then(Mono.just(ResponseEntity
                        .status(HttpStatus.FORBIDDEN)
                        .body(AuthResponse.builder()
                                .success(false)
                                .message("Email not verified")
                                .warning("Please verify your email before logging in. " +
                                        "A new verification link has been sent.")
                                .build())
                ))
                .onErrorResume(e -> {
                    log.error("Failed to resend verification at {}: {}", now, e.getMessage());
                    return Mono.just(ResponseEntity
                            .status(HttpStatus.FORBIDDEN)
                            .body(AuthResponse.builder()
                                    .success(false)
                                    .message("Email not verified")
                                    .warning("Please verify your email before logging in.")
                                    .build())
                    );
                });
    }

    /**
     * Get admin permissions
     */
    private Set<String> getAdminPermissions() {
        return Set.of(
                "ADMIN_READ",
                "ADMIN_WRITE",
                "USER_MANAGEMENT",
                "SYSTEM_CONFIG"
        );
    }
}