package com.techStack.authSys.auth.controller;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.auth.dto.LoginRequest;
import com.techStack.authSys.auth.dto.LoginResponse;
import com.techStack.authSys.auth.dto.ResendVerificationRequest;
import com.techStack.authSys.auth.service.*;
import com.techStack.authSys.common.dto.ApiResponse;
import com.techStack.authSys.common.util.HelperUtils;
import com.techStack.authSys.identity.dto.UserRegistrationDTO;
import com.techStack.authSys.identity.models.User;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Authentication Controller
 *
 * Handles user registration, authentication, and session management.
 * Supports first-time setup and OTP verification flows.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Tag(
        name = "Authentication",
        description = """
                User authentication and account management.
                
                **Features:**
                - User registration with email verification
                - Login with multiple flows (first-time, OTP, normal)
                - Email verification and resend
                - Session management and logout
                - Account availability checks
                
                **Login Flows:**
                1. **First-Time Login**: Password change + OTP verification required
                2. **2FA Login**: OTP verification required for users with verified phone
                3. **Normal Login**: Direct access for users without OTP
                
                **Security:**
                - Email verification required before login
                - Rate limiting on sensitive endpoints
                - Device fingerprinting
                - Session tracking
                """
)
public class AuthController {

    /* =========================
       Dependencies
       ========================= */

    private final AuthService authService;
    private final AuthenticationOrchestrator authenticationOrchestrator;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final DeviceVerificationService deviceVerificationService;
    private final LogoutService logoutService;
    private final Clock clock;

    /* =========================
       User Registration
       ========================= */

    @Operation(
            summary = "Register New User",
            description = """
                    Create a new user account.
                    
                    **Registration Process:**
                    1. Submit registration form
                    2. System creates account (status: PENDING_APPROVAL)
                    3. Verification email sent
                    4. User verifies email
                    5. Account activated
                    
                    **Required Fields:**
                    - Email (unique, valid format)
                    - Password (min 8 chars, complexity rules)
                    - First name
                    - Last name
                    - Phone number (E.164 format)
                    
                    **Password Requirements:**
                    - Minimum 8 characters
                    - At least one uppercase letter
                    - At least one lowercase letter
                    - At least one number
                    - At least one special character
                    
                    **After Registration:**
                    - Check email for verification link
                    - Click link to verify email
                    - Login at POST /api/auth/login
                    """,
            security = {}  // No authentication required
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "201",
                    description = "User registered successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Registration successful! Please check your email to verify your account.",
                                              "data": {
                                                "id": "user-123",
                                                "email": "user@example.com",
                                                "firstName": "John",
                                                "lastName": "Doe",
                                                "status": "PENDING_APPROVAL",
                                                "emailVerified": false
                                              }
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
                    responseCode = "500",
                    description = "Failed to send verification email"
            )
    })
    @PostMapping("/register")
    public Mono<ResponseEntity<ApiResponse<User>>> registerUser(
            @Parameter(
                    description = "User registration details",
                    required = true,
                    schema = @Schema(implementation = UserRegistrationDTO.class)
            )
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
    }

    /* =========================
       Email Verification
       ========================= */

    @Operation(
            summary = "Resend Email Verification Link",
            description = """
                Sends a new email verification link to an account that has not yet been verified.
                
                **When to Use**
                - Verification email was not received
                - Previous verification link expired
                - User accidentally deleted the verification email
                
                **Security & Privacy**
                - No authentication required
                - For security reasons, the API may return a generic success response even when the email address is not registered
                - Verification links have a limited validity period
                - Requests are subject to rate limiting to prevent abuse
                
                **Rate Limits**
                - Maximum 3 requests per hour per email address
                - Excessive requests may result in HTTP 429 (Too Many Requests)
                
                **Next Steps**
                1. Check your inbox and spam/junk folder
                2. Open the verification email
                3. Click the verification link
                4. Once verified, sign in to your account
                
                **Access**
                - Public endpoint
                """,
            security = {}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Verification email request processed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                        {
                                          "success": true,
                                          "message": "If an account exists and requires verification, a verification email has been sent.",
                                          "data": null
                                        }
                                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid email address or malformed request"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Rate limit exceeded. Please wait before requesting another verification email"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Internal server error while processing verification request"
            )
    })
    @PostMapping("/resend-verification")
    public Mono<ResponseEntity<ApiResponse<Void>>> resendVerificationEmail(
            @Valid @RequestBody ResendVerificationRequest request,
            ServerWebExchange exchange) {
        String email = request.email();
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
    }

    @Operation(
            summary = "Verify Email Address",
            description = """
                    Verify user email using verification token.
                    
                    **Process:**
                    1. User clicks link in verification email
                    2. Browser redirects to this endpoint with token
                    3. Token validated and email marked as verified
                    4. User redirected to login page
                    
                    **Token Properties:**
                    - Single use only
                    - Expires in 24 hours
                    - Cannot be reused after verification
                    
                    **After Verification:**
                    - Email verified successfully
                    - Can login at POST /api/auth/login
                    - Account fully activated
                    """,
            security = {}  // No authentication required
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Email verified successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Email verified successfully. You can now log in.",
                                              "data": null
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid or expired token"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "User not found"
            )
    })
    @GetMapping("/verify-email")
    public Mono<ResponseEntity<ApiResponse<Object>>> verifyEmail(
            @Parameter(
                    description = "Email verification token",
                    required = true,
                    example = "eyJhbGciOiJIUzUxMiJ9..."
            )
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
    }

    /* =========================
       User Login
       ========================= */

    @Operation(
            summary = "User Login",
            description = """
                    Authenticate user with email and password.
                    
                    **Login Flows:**
                    
                    **1. First-Time Login (New User):**
                    - User has `forcePasswordChange = true`
                    - Returns: `firstTimeLogin: true` + temporary token
                    - Next: POST /api/auth/first-time-setup/change-password
                    - Then: POST /api/auth/first-time-setup/verify-otp
                    
                    **2. Login with OTP (Returning User with 2FA):**
                    - User has `phoneVerified = true`
                    - Returns: `requiresOtp: true` + temporary token
                    - OTP sent to registered phone
                    - Next: POST /api/auth/login-otp/verify
                    
                    **3. Normal Login (No OTP):**
                    - Phone not verified OR OTP disabled
                    - Returns: Full access tokens immediately
                    - Can access all authenticated endpoints
                    
                    **Response Handling:**
```javascript
                    if (response.firstTimeLogin) {
                      // Redirect to first-time setup
                      navigate('/first-time-setup');
                    } else if (response.requiresOtp) {
                      // Redirect to OTP verification
                      navigate('/verify-otp');
                    } else {
                      // Login complete - save tokens
                      saveTokens(response.accessToken, response.refreshToken);
                      navigate('/dashboard');
                    }
```
                    
                    **Security:**
                    - Rate limited: 10 attempts per 15 minutes
                    - Account locks after 5 failed attempts
                    - Device fingerprinting enabled
                    - Session tracking active
                    """,
            security = {}  // No authentication required for login
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Login successful (normal flow)",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Login successful",
                                              "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
                                              "refreshToken": "eyJhbGciOiJIUzUxMiJ9...",
                                              "accessTokenExpiry": "2024-03-15T12:30:00Z",
                                              "refreshTokenExpiry": "2024-03-22T12:00:00Z",
                                              "userInfo": {
                                                "userId": "user-123",
                                                "email": "user@example.com",
                                                "firstName": "John",
                                                "lastName": "Doe",
                                                "roles": ["USER"]
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "First-time setup or OTP required",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "First-Time Setup Required",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "First-time login detected. Please change your password.",
                                                      "data": {
                                                        "firstTimeLogin": true,
                                                        "requiresOtp": false,
                                                        "temporaryToken": "eyJhbGc...",
                                                        "userId": "user-123"
                                                      }
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "OTP Verification Required",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "OTP sent to your phone.",
                                                      "data": {
                                                        "firstTimeLogin": false,
                                                        "requiresOtp": true,
                                                        "temporaryToken": "eyJhbGc...",
                                                        "userId": "user-123"
                                                      }
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid credentials"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Email not verified or account disabled"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Too many login attempts"
            )
    })
    @PostMapping("/login")
    public Mono<ResponseEntity<ApiResponse<LoginResponse>>> login(
            @Parameter(
                    description = "Login credentials",
                    required = true,
                    schema = @Schema(implementation = LoginRequest.class)
            )
            @Valid @RequestBody LoginRequest loginRequest,

            @Parameter(
                    description = "User agent string for device tracking",
                    example = "Mozilla/5.0..."
            )
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
                        loginTime,
                        deviceFingerprint,
                        userAgent,
                        "USER_LOGIN",
                        this,
                        List.of()
                )
                .map(authResult -> {
                    LoginResponse response = LoginResponse.success(
                            authResult.getAccessToken(),
                            authResult.getRefreshToken(),
                            authResult.getUser(),
                            "Login successful"
                    );

                    return ResponseEntity.ok(
                            new ApiResponse<>(true, "Login successful", response)
                    );
                })
                .onErrorResume(com.techStack.authSys.auth.exception.FirstTimeSetupRequiredException.class, e -> {
                    log.warn("⚠️ First-time setup required for: {}",
                            HelperUtils.maskEmail(loginRequest.getEmail()));

                    LoginResponse response = LoginResponse.firstTimeLogin(
                            e.getTemporaryToken(),
                            e.getUserId(),
                            e.getMessage()
                    );

                    return Mono.just(ResponseEntity.ok(
                            new ApiResponse<>(true, e.getMessage(), response)
                    ));
                })
                .onErrorResume(com.techStack.authSys.auth.exception.OtpVerificationRequiredException.class, e -> {
                    log.info("📱 OTP verification required for: {}",
                            HelperUtils.maskEmail(loginRequest.getEmail()));

                    LoginResponse response = LoginResponse.loginOtpRequired(
                            e.getTemporaryToken(),
                            e.getUserId(),
                            e.getMessage()
                    );

                    return Mono.just(ResponseEntity.ok(
                            new ApiResponse<>(true, e.getMessage(), response)
                    ));
                })
                .onErrorResume(com.techStack.authSys.auth.exception.AuthException.class, e -> {
                    log.error("❌ Auth error: {}", e.getMessage());
                    return Mono.just(
                            ResponseEntity.status(e.getHttpStatus())
                                    .body(new ApiResponse<>(false, e.getMessage(), null))
                    );
                })
                .doOnSuccess(res -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(loginTime, completionTime);
                    log.info("✅ Login processed at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(loginRequest.getEmail()));
                });
    }

    /* =========================
       User Logout
       ========================= */

    @Operation(
            summary = "Logout User",
            description = """
                    Invalidate current user session and tokens.
                    
                    **Process:**
                    1. Extract JWT from Authorization header
                    2. Add token to blacklist
                    3. Clear device fingerprint
                    4. Invalidate session
                    
                    **After Logout:**
                    - Access token invalidated
                    - Refresh token invalidated
                    - Must login again to access system
                    
                    **Client Actions:**
                    - Clear stored tokens
                    - Redirect to login page
                    - Clear any cached user data
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Logout successful",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Logged out successfully",
                                              "data": null
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired token"
            )
    })
    @PostMapping("/logout")
    public Mono<ResponseEntity<ApiResponse<Void>>> logout(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            ServerWebExchange exchange) {

        Instant logoutTime = clock.instant();

        String ipAddress = deviceVerificationService.extractClientIp(exchange);

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
    }

    /* =========================
   Current User
   ========================= */

    @Operation(
            summary = "Get Current User",
            description = """
                Returns the authenticated user's own session data — the same
                User record populated at login (roles, verification flags,
                account status). Distinct from GET /api/user/profile, which
                returns the separate, optional UserProfile record (bio,
                department, etc).
                
                **Authentication required.**
                """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Current user retrieved successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Not authenticated"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Authenticated user's record could not be found"
            )
    })
    @GetMapping("/me")
    public Mono<ResponseEntity<ApiResponse<User>>> getCurrentUser() {
        Instant requestTime = clock.instant();

        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication().getPrincipal())
                .flatMap(principal -> {
                    if (principal instanceof CustomUserDetails cud) {
                        return Mono.just(cud.getUserId());
                    }
                    if (principal instanceof String firebaseUid) {
                        return Mono.just(firebaseUid);
                    }
                    return Mono.error(new IllegalStateException(
                            "Unrecognized principal type: " + principal.getClass()));
                })
                .flatMap(firebaseServiceAuth::getUserById)
                // getUserById → FirestoreUserRepository.findById errors with
                // UserNotFoundException directly on a miss — it never completes
                // empty, so no switchIfEmpty here; the onErrorResume below
                // translates it into a proper HTTP response instead of letting
                // it fall through to GlobalExceptionHandler as a raw 500.
                .map(user -> {
                    log.debug("✅ Current user resolved at {} for: {}",
                            clock.instant(), HelperUtils.maskEmail(user.getEmail()));
                    return ResponseEntity.ok(
                            new ApiResponse<>(true, "Current user retrieved", user));
                })
                .onErrorResume(com.techStack.authSys.identity.exception.UserNotFoundException.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                                .body(new ApiResponse<>(false, e.getMessage(), null))))
                .doOnError(e -> log.error("Error resolving current user at {}: {}",
                        requestTime, e.getMessage()));
    }

    /* =========================
       Email Availability
       ========================= */

    @Operation(
            summary = "Check Email Availability",
            description = """
                    Check if email address is available for registration.
                    
                    **Use Cases:**
                    - Real-time validation during registration
                    - Pre-registration checks
                    - Form validation feedback
                    
                    **Returns:**
                    - `true`: Email available for registration
                    - `false`: Email already in use
                    
                    **No Authentication Required**
                    """,
            security = {}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Email availability checked",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Available",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "Email is available",
                                                      "data": true
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Not Available",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "Email is already registered",
                                                      "data": false
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid email format"
            )
    })
    @GetMapping("/check-email")
    public Mono<ResponseEntity<ApiResponse<Boolean>>> checkEmailAvailability(
            @Parameter(
                    description = "Email address to check",
                    required = true,
                    example = "user@example.com"
            )
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
    }

    /* =========================
       Private Helper Methods
       ========================= */
    /**
     * Extract JWT token from Authorization header
     */
    private String extractToken(String authHeader) {
        return authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
    }
}