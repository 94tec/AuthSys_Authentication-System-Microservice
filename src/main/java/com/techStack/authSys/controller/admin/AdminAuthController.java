package com.techStack.authSys.controller.admin;

import com.techStack.authSys.dto.internal.AuthResult;
import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.dto.response.BootstrapResult;
import com.techStack.authSys.models.authorization.Permissions;
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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
     * Manual Super Admin registration endpoint.
     * Returns detailed result about what actually happened.
     */
    @PostMapping("/register")
    public Mono<ResponseEntity<ApiResponse<BootstrapResult>>> registerSuperAdmin(
            @RequestParam String email,
            @RequestParam String phone) {

        Instant startTime = clock.instant();

        log.warn("🚨 Manual Super Admin registration initiated at {} for: {}",
                startTime, HelperUtils.maskEmail(email));

        return transactionalBootstrapService.createSuperAdminTransactionally(email, phone)
                .map(result -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.info("✅ Super Admin registration completed at {} in {} | created={} exists={} emailSent={}",
                            endTime, duration,
                            result.created(),
                            result.alreadyExists(),
                            result.emailSent());

                    // Use 201 CREATED if new, 200 OK if already exists
                    HttpStatus status = result.created() ? HttpStatus.CREATED : HttpStatus.OK;

                    ApiResponse<BootstrapResult> response = new ApiResponse<>(
                            true,
                            result.message(),
                            result
                    );

                    return ResponseEntity.status(status).body(response);
                });

        // ❗ Error handling delegated to GlobalExceptionHandler
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            ServerWebExchange exchange) {

        Instant loginTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(ipAddress, userAgent);

        log.info("Login attempt at {} for: {} from IP: {}",
                loginTime,
                HelperUtils.maskEmail(loginRequest.getEmail()),
                ipAddress);

        return authenticationOrchestrator.authenticate(
                        loginRequest.getEmail(),
                        loginRequest.getPassword(),
                        ipAddress,
                        loginTime,
                        deviceFingerprint,
                        userAgent,
                        "LOGIN",
                        this,
                        Set.of() // client cannot supply permissions
                )
                .map(authResult -> {
                    User user = authResult.getUser();

                    // Convert Roles enum -> Set<String> for response
                    Set<String> roleNames = user.getRoles().stream()
                            .map(Enum::name)
                            .collect(Collectors.toSet());

                    // Map AuthResult → AuthResponse
                    AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
                            .userId(user.getId())
                            .email(user.getEmail())
                            .firstName(user.getFirstName())
                            .lastName(user.getLastName())
                            .roles(roleNames)
                            .mfaRequired(user.isMfaRequired())
                            .profilePictureUrl(user.getProfilePictureUrl())
                            .build();

                    // Permissions are server-resolved from User.getAllPermissions()
                    List<Permissions> permissions = new ArrayList<>(user.getAllPermissions());

                    return AuthResponse.success(
                            authResult.getAccessToken(),
                            authResult.getRefreshToken(),
                            authResult.getAccessTokenExpiry(),
                            authResult.getRefreshTokenExpiry(),
                            userInfo,
                            permissions
                    );
                })
                .map(ResponseEntity::ok)
                .doOnSuccess(res -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(loginTime, completionTime);

                    log.info("✅ Login successful at {} in {} for {}",
                            completionTime, duration, HelperUtils.maskEmail(loginRequest.getEmail()));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(loginTime, errorTime);

                    log.error("❌ Login failed at {} after {} for {}: {}",
                            errorTime, duration, HelperUtils.maskEmail(loginRequest.getEmail()), e.getMessage());
                });
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
            @Valid @RequestBody UserRegistrationDTO userDto,
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
    private Mono<ResponseEntity<AuthResponse>> handleAdminLoginResult(AuthResult authResult, String ipAddress, Instant loginTime) {

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

}