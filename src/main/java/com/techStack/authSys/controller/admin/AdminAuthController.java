package com.techStack.authSys.controller.admin;

import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.dto.response.BootstrapResult;
import com.techStack.authSys.dto.response.LoginResponse;
import com.techStack.authSys.models.authorization.Permissions;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.AuthenticationOrchestrator;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.service.bootstrap.AdminUserManagementService;
import com.techStack.authSys.service.bootstrap.TransactionalBootstrapService;
import com.techStack.authSys.util.validation.HelperUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
 * Includes first-time setup detection and OTP flow.
 */
@Slf4j
@RestController
@RequestMapping("/api/super-admin")
@RequiredArgsConstructor
@Tag(
        name = "Super Admin",
        description = """
                Super Administrator operations and bootstrap.
                
                **Features:**
                - Bootstrap initial Super Admin
                - Admin user management
                - First-time setup enforcement
                - OTP verification (2FA)
                - Full system access
                
                **Security:**
                - SUPER_ADMIN role required for most operations
                - First-time login forces password change
                - OTP verification on every login
                - Audit logging for all operations
                
                **Access Levels:**
                - Bootstrap: Public (one-time only)
                - Login: Public (with credentials)
                - Admin Registration: SUPER_ADMIN only
                """
)
public class AdminAuthController {

    /* =========================
       Dependencies
       ========================= */

    private final AuthenticationOrchestrator authenticationOrchestrator;
    private final TransactionalBootstrapService transactionalBootstrapService;
    private final AdminUserManagementService adminUserManagementService;
    private final DeviceVerificationService deviceVerificationService;
    private final Clock clock;

    /* =========================
       Super Admin Bootstrap
       ========================= */

    @Operation(
            summary = "Bootstrap Super Admin",
            description = """
                    Create the initial Super Admin account.
                    
                    **One-Time Operation:**
                    - Can only be executed once
                    - If Super Admin exists, returns existing details
                    - Sends temporary password via email
                    
                    **After Bootstrap:**
                    1. Check email for temporary password
                    2. Login at POST /api/super-admin/login
                    3. Change password (first-time setup)
                    4. Verify OTP sent to phone
                    5. Get full system access
                    
                    **Phone Format:**
                    - Must be in E.164 format
                    - Example: +254712345678
                    
                    **Security:**
                    - No authentication required (bootstrap only)
                    - Temporary password expires in 24 hours
                    - Forces password change on first login
                    - Requires phone OTP verification
                    """,
            security = {}  // No security for bootstrap
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "201",
                    description = "Super Admin created successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Super Admin created successfully. Check email for temporary password.",
                                              "data": {
                                                "created": true,
                                                "alreadyExists": false,
                                                "emailSent": true,
                                                "userId": "super-admin-id-123",
                                                "requiresFirstTimeSetup": true,
                                                "message": "Super Admin created. Check email."
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Super Admin already exists",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Super Admin already exists",
                                              "data": {
                                                "created": false,
                                                "alreadyExists": true,
                                                "emailSent": false,
                                                "userId": "existing-super-admin-id",
                                                "requiresFirstTimeSetup": false,
                                                "message": "Super Admin already exists"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid email or phone format"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Failed to send email or create account"
            )
    })
    @PostMapping("/register")
    public Mono<ResponseEntity<ApiResponse<BootstrapResult>>> registerSuperAdmin(
            @Parameter(
                    description = "Super Admin email address",
                    required = true,
                    example = "admin@techstack.com"
            )
            @RequestParam String email,

            @Parameter(
                    description = "Phone number in E.164 format",
                    required = true,
                    example = "+254712345678"
            )
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

                    HttpStatus status = result.created() ? HttpStatus.CREATED : HttpStatus.OK;

                    ApiResponse<BootstrapResult> response = new ApiResponse<>(
                            true,
                            result.message(),
                            result
                    );

                    return ResponseEntity.status(status).body(response);
                });
    }

    /* =========================
       Super Admin Login
       ========================= */

    @Operation(
            summary = "Super Admin Login",
            description = """
                    Authenticate Super Admin with email and password.
                    
                    **Login Flows:**
                    
                    **1. First-Time Login:**
                    - User has `forcePasswordChange = true`
                    - Returns temporary token (30 min validity)
                    - Must change password: POST /api/auth/first-time-setup/change-password
                    - Then verify OTP: POST /api/auth/first-time-setup/verify-otp
                    
                    **2. Returning User (with OTP):**
                    - OTP sent to registered phone
                    - Returns temporary token (5 min validity)
                    - Must verify OTP: POST /api/auth/login-otp/verify
                    
                    **3. Normal Login (no OTP):**
                    - Phone not verified OR OTP disabled
                    - Returns full access tokens immediately
                    
                    **Response Types:**
                    - `firstTimeLogin: true` → Go to first-time setup flow
                    - `requiresOtp: true` → Go to OTP verification flow
                    - `accessToken` present → Login complete
                    
                    **Security:**
                    - Rate limited: 10 attempts per 15 minutes
                    - Account locks after 5 failed attempts
                    - Requires MFA for Super Admin
                    """,
            security = {}  // No security required for login endpoint
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Login successful (normal flow)",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AuthResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Login successful",
                                              "data": {
                                                "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
                                                "refreshToken": "eyJhbGciOiJIUzUxMiJ9...",
                                                "accessTokenExpiry": "2024-03-15T12:30:00Z",
                                                "refreshTokenExpiry": "2024-03-22T12:00:00Z",
                                                "userInfo": {
                                                  "userId": "super-admin-123",
                                                  "email": "admin@techstack.com",
                                                  "firstName": "System",
                                                  "lastName": "Administrator",
                                                  "roles": ["SUPER_ADMIN"],
                                                  "mfaRequired": true
                                                },
                                                "permissions": ["USER_CREATE", "USER_DELETE", "SYSTEM_CONFIG"]
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "First-time setup required",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "First-time login detected. Please change your password to continue.",
                                              "data": {
                                                "firstTimeLogin": true,
                                                "requiresOtp": false,
                                                "temporaryToken": "eyJhbGciOiJIUzUxMiJ9...",
                                                "userId": "super-admin-123",
                                                "message": "Change password required"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "OTP verification required",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "OTP sent to your phone. Please verify to continue.",
                                              "data": {
                                                "firstTimeLogin": false,
                                                "requiresOtp": true,
                                                "temporaryToken": "eyJhbGciOiJIUzUxMiJ9...",
                                                "userId": "super-admin-123",
                                                "message": "Check your phone for OTP"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Too many login attempts"
            )
    })
    @PostMapping("/login")
    public Mono<ResponseEntity<ApiResponse<Object>>> login(  // ✅ Fixed: use Object instead of ?
                                                             @Parameter(
                                                                     description = "Login credentials",
                                                                     required = true,
                                                                     schema = @Schema(implementation = LoginRequest.class)
                                                             )
                                                             @Valid @RequestBody LoginRequest loginRequest,

                                                             @Parameter(
                                                                     description = "User agent string",
                                                                     example = "Mozilla/5.0..."
                                                             )
                                                             @RequestHeader(value = "User-Agent", required = false) String userAgent,

                                                             ServerWebExchange exchange) {

        Instant loginTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(ipAddress, userAgent);

        log.info("Admin login attempt at {} for: {} from IP: {}",
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
                        "ADMIN_LOGIN",
                        this,
                        Set.of()
                )
                .map(authResult -> {
                    User user = authResult.getUser();

                    Set<String> roleNames = user.getRoles().stream()
                            .map(Enum::name)
                            .collect(Collectors.toSet());

                    AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
                            .userId(user.getId())
                            .email(user.getEmail())
                            .firstName(user.getFirstName())
                            .lastName(user.getLastName())
                            .roles(roleNames)
                            .mfaRequired(user.isMfaRequired())
                            .profilePictureUrl(user.getProfilePictureUrl())
                            .build();

                    List<Permissions> permissions = new ArrayList<>(user.getAllPermissions());

                    AuthResponse authResponse = AuthResponse.success(
                            authResult.getAccessToken(),
                            authResult.getRefreshToken(),
                            authResult.getAccessTokenExpiry(),
                            authResult.getRefreshTokenExpiry(),
                            userInfo,
                            permissions
                    );

                    // ✅ Fixed: cast to Object instead of wildcard
                    return ResponseEntity.ok(
                            new ApiResponse<Object>(true, "Login successful", authResponse)
                    );
                })
                .doOnSuccess(res -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(loginTime, completionTime);
                    log.info("✅ Admin login successful at {} in {} for {}",
                            completionTime, duration, HelperUtils.maskEmail(loginRequest.getEmail()));
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(loginTime, errorTime);
                    log.error("❌ Admin login failed at {} after {} for {}: {}",
                            errorTime, duration, HelperUtils.maskEmail(loginRequest.getEmail()), e.getMessage());
                });
    }

    /* =========================
       Admin User Registration
       ========================= */

    @Operation(
            summary = "Register New Admin",
            description = """
                    Create a new Admin user account (SUPER_ADMIN only).
                    
                    **Requirements:**
                    - Caller must have SUPER_ADMIN role
                    - Valid email and phone number
                    - Unique email address
                    
                    **Automatic Actions:**
                    - Generates temporary password
                    - Sends credentials via email
                    - Sets `forcePasswordChange = true`
                    - Sets initial role to ADMIN
                    
                    **New Admin Flow:**
                    1. Receives email with temporary password
                    2. Login at POST /api/super-admin/login
                    3. Complete first-time setup
                    4. Verify phone with OTP
                    5. Get full access
                    
                    **Permissions:**
                    - Can manage regular users
                    - Cannot create other Super Admins
                    - Cannot modify Super Admin accounts
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "201",
                    description = "Admin created successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Admin user created successfully. Credentials sent to email.",
                                              "data": "admin-user-id-456"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid input or email already exists"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Authentication required"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "SUPER_ADMIN role required"
            )
    })
    @PostMapping("/register-admin")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public Mono<ResponseEntity<ApiResponse<String>>> registerAdmin(
            @Parameter(
                    description = "Admin user details",
                    required = true,
                    schema = @Schema(implementation = UserRegistrationDTO.class)
            )
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
    }
}