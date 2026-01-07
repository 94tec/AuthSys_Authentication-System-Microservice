package com.techStack.authSys.controller;

import com.techStack.authSys.dto.*;
import com.techStack.authSys.service.DeviceVerificationService;
import com.techStack.authSys.service.authentication.AuthenticationOrchestrator;
import com.techStack.authSys.service.authentication.LoginResponseBuilder;
import com.techStack.authSys.service.bootstrap.AdminUserManagementService;
import com.techStack.authSys.service.bootstrap.SuperAdminCreationService;
import com.techStack.authSys.service.verification.EmailVerificationService;
import com.techStack.authSys.util.HelperUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Refactored Admin Authentication Controller.
 * Handles Super Admin and Admin user operations with proper separation of concerns.
 */
@Slf4j
@RestController
@RequestMapping("/api/super-admin")
@RequiredArgsConstructor
public class AdminAuthController {

    // Authentication Services
    private final AuthenticationOrchestrator authenticationOrchestrator;
    private final LoginResponseBuilder loginResponseBuilder;

    // Admin Management Services
    private final SuperAdminCreationService superAdminCreationService;
    private final AdminUserManagementService adminUserManagementService;

    // Support Services
    private final DeviceVerificationService deviceVerificationService;
    private final EmailVerificationService emailVerificationService;

    /**
     * Manually registers a Super Admin (for emergency situations).
     * Should be disabled in production or protected by additional security.
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ResponseEntity<ApiResponse<Object>>> registerSuperAdmin(
            @RequestParam String email,
            @RequestParam String phone) {

        log.warn("🚨 Manual Super Admin registration initiated for: {}", HelperUtils.maskEmail(email));

        return superAdminCreationService.createSuperAdminIfAbsent(email, phone)
                .then(Mono.just(ResponseEntity
                        .status(HttpStatus.CREATED)
                        .body(new ApiResponse<>(
                                true,
                                "Super Admin created successfully. Check email for credentials.",
                                null
                        ))
                ))
                .onErrorResume(e -> {
                    log.error("❌ Manual Super Admin registration failed: {}", e.getMessage(), e);
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

    /**
     * Authenticates Super Admin or Admin users.
     */
    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            ServerWebExchange exchange) {

        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress, userAgent);

        log.info("Admin login attempt for: {} from IP: {}",
                HelperUtils.maskEmail(loginRequest.getEmail()), ipAddress);
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
                .doOnSuccess(res -> log.info("✅ Admin login successful for: {}",
                        HelperUtils.maskEmail(loginRequest.getEmail())));

        // Error handling delegated to GlobalExceptionHandler
    }

    /**
     * Registers a new Admin user (Super Admin only).
     */
    @PostMapping("/register-admin")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<String>>> registerAdmin(
            @Valid @RequestBody UserDTO userDto,
            ServerWebExchange exchange) {

        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress, userDto.getUserAgent());

        log.info("Admin registration by Super Admin for: {}", HelperUtils.maskEmail(userDto.getEmail()));

        return adminUserManagementService.createAdminUser(userDto, exchange, ipAddress, deviceFingerprint)
                .map(user -> ResponseEntity
                        .status(HttpStatus.CREATED)
                        .body(new ApiResponse<>(
                                true,
                                "Admin user created successfully. Credentials sent to email.",
                                user.getId()
                        ))
                );

        // Error handling delegated to GlobalExceptionHandler
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    /**
     * Handles admin login result, checking email verification.
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
     * Handles login with unverified email.
     */
    private Mono<ResponseEntity<AuthResponse>> handleUnverifiedAdminEmail(
            com.techStack.authSys.models.User user,
            String ipAddress) {

        log.warn("Admin login attempt with unverified email: {}", HelperUtils.maskEmail(user.getEmail()));

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
                    log.error("Failed to resend verification: {}", e.getMessage());
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

    // Helper method to get admin permissions
    private Set<String> getAdminPermissions() {
        return Set.of(
                "ADMIN_READ",
                "ADMIN_WRITE",
                "USER_MANAGEMENT",
                "SYSTEM_CONFIG"
                // Add other admin permissions as needed
        );
    }
}