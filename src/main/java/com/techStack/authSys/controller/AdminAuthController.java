package com.techStack.authSys.controller;

import java.security.Principal;
import java.time.Instant;
import java.util.List;

import com.techStack.authSys.dto.AuthResponse;
import com.techStack.authSys.dto.AuthResult;
import com.techStack.authSys.dto.LoginRequest;
import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.models.Permissions;
import com.techStack.authSys.repository.MetricsService;
import com.techStack.authSys.repository.PermissionProvider;
import com.techStack.authSys.service.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/super-admin")
@RequiredArgsConstructor
@Slf4j
public class AdminAuthController {
    private static final Logger logger = LoggerFactory.getLogger(AdminAuthController.class);

    private final SuperAdminService superAdminService;
    private final DeviceVerificationService deviceVerificationService;
    private final EmailServiceInstance1 emailServiceInstance1;
    private final AuditLogService auditLogService;
    private final JwtService jwtService;
    private final PermissionProvider permissionProvider;
    private final BootstrapFlagService bootstrapFlagService;
    private final MetricsService metricsService;
    private final RedisCacheService redisCacheService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RoleAssignmentService roleAssignmentService;
    private final EmailServiceInstance1 emailService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ResponseEntity<String>> registerSuperAdmin(
            @RequestParam String email,
            @RequestParam String phone
    ) {
        return superAdminService.registerSuperAdmin(email, phone)
                .map(message -> ResponseEntity.ok(message))
                .onErrorResume(e -> {
                    log.error("❌ Super admin registration failed: {}", e.getMessage(), e);
                    return Mono.just(ResponseEntity.badRequest().body(e.getMessage()));
                });
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> authenticateUser(
            @Valid @RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "User-Agent", required = false) String userAgent,
            ServerWebExchange exchange) {

        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(ipAddress, userAgent);

        return superAdminService.login(
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
                        return emailServiceInstance1.sendVerificationEmail(authResult.getUser().getId(), ipAddress)
                                .thenReturn(
                                        ResponseEntity.status(HttpStatus.FORBIDDEN)
                                                .body(AuthResponse.builder()
                                                        .warning("Email not verified. Verification email resent")
                                                        .build())
                                );
                    }
                    return handleLoginSuccess(authResult, ipAddress, deviceFingerprint, userAgent);
                })
                .doOnSuccess(res -> logger.info("✅ Successful login for Administrator User {}", loginRequest.getEmail()))
                .onErrorResume(CustomException.class, e -> {
                    logger.warn("⚠️ Login failed for Administrator {}: {}", loginRequest.getEmail(), e.getMessage());
                    auditLogService.logAuthFailure(loginRequest.getEmail(), ipAddress, deviceFingerprint, e.getMessage());
                    return Mono.just(ResponseEntity.status(e.getStatusCode())
                            .body(AuthResponse.builder()
                                    .warning(e.getReason())
                                    .build()));
                })
                .onErrorResume(e -> {
                    logger.error("❌ Unexpected Administrator login error for {}: {}", loginRequest.getEmail(), e.getMessage(), e);
                    return Mono.just(ResponseEntity.internalServerError().build());
                });
    }
    private Mono<ResponseEntity<AuthResponse>> handleLoginSuccess(AuthResult authResult, String ipAddress, String deviceFingerprint, String userAgent) {
        AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
                .userId(authResult.getUser().getId())
                .email(authResult.getUser().getEmail())
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
        // Log the token pair and context info
        logger.info("✅ Generated token pair for userId={}", userInfo.getUserId());

        return Mono.just(ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, response.getAccessToken())
                .body(response));
    }

    @PostMapping("/logout")
    public Mono<ResponseEntity<String>> logout(ServerWebExchange exchange, Principal principal) {
        String ipAddress = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        String sessionId = exchange.getRequest().getHeaders().getFirst("sessionId");

        if (principal == null || sessionId == null) {
            return Mono.just(ResponseEntity.badRequest().body("Missing principal or sessionId"));
        }

        String userId = principal.getName(); // Auto from JWT or security context

        return superAdminService.logout(userId, sessionId, ipAddress)
                .thenReturn(ResponseEntity.ok("Logout successful"));
    }

    //SUPER ADMIN - REGISTER ADMIN ROUTE
    @PostMapping("/register-admin")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<String>> registerAdmin(
            @RequestBody UserDTO userDto,
            ServerWebExchange exchange) {

        String ipAddress = exchange.getRequest().getRemoteAddress() != null
                ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress().split("%")[0] // Removes zone index
                : "unknown";

        return superAdminService.createAdminUser(userDto, exchange)
                .map(user -> {
                    logger.info("Administrator registered successfully: {}", user.getEmail());
                    return ResponseEntity.ok("User registered successfully. Please check your email for verification." + user);
                })
                .onErrorResume(CustomException.class, e -> {
                    logger.warn("User registration failed: {}", e.getMessage());
                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body("Registration failed: " + e.getMessage()));
                })
                .onErrorResume(Exception.class, e -> {
                    logger.error("Unexpected registration error", e);
                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("User registration failed due to an unexpected error."));
                });
    }

}







