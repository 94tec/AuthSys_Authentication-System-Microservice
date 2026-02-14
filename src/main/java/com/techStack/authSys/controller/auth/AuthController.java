package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.AuthResponse;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.*;
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
import java.util.Set;
import java.util.stream.Collectors;

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
            summary = "Resend Verification Email",
            description = """
                    Resend email verification link.
                    
                    **Use Cases:**
                    - Original email not received
                    - Verification link expired (24 hours)
                    - Email accidentally deleted
                    
                    **Rate Limiting:**
                    - Maximum 3 requests per hour per email
                    
                    **After Receiving Email:**
                    - Click verification link
                    - Email automatically verified
                    - Can now login
                    """,
            security = {}  // No authentication required
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Verification email sent",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Verification email sent successfully. Please check your inbox.",
                                              "data": null
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "Email not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Too many requests"
            )
    })
    @PostMapping("/resend-verification")
    public Mono<ResponseEntity<ApiResponse<Void>>> resendVerificationEmail(
            @Parameter(
                    description = "Email address to resend verification to",
                    required = true,
                    example = "user@example.com"
            )
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
                            schema = @Schema(implementation = AuthResponse.class),
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
    public Mono<ResponseEntity<ApiResponse<Object>>> login(  // ✅ Fixed: use Object
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
                        Set.of()
                )
                .map(authResult -> {
                    Set<String> roleNames = authResult.getUser().getRoles().stream()
                            .map(Enum::name)
                            .collect(Collectors.toSet());

                    AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
                            .userId(authResult.getUser().getId())
                            .email(authResult.getUser().getEmail())
                            .firstName(authResult.getUser().getFirstName())
                            .lastName(authResult.getUser().getLastName())
                            .roles(roleNames)
                            .mfaRequired(authResult.getUser().isMfaRequired())
                            .profilePictureUrl(authResult.getUser().getProfilePictureUrl())
                            .build();

                    AuthResponse authResponse = AuthResponse.success(
                            authResult.getAccessToken(),
                            authResult.getRefreshToken(),
                            authResult.getAccessTokenExpiry(),
                            authResult.getRefreshTokenExpiry(),
                            userInfo,
                            authResult.getPermissions()
                    );

                    // ✅ Fixed: cast to Object
                    return ResponseEntity.ok(
                            new ApiResponse<Object>(true, "Login successful", authResponse)
                    );
                })
                .doOnSuccess(res -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(loginTime, completionTime);
                    log.info("✅ Login successful at {} in {} for: {}",
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
            @Parameter(
                    description = "JWT access token",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzUxMiJ9..."
            )
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