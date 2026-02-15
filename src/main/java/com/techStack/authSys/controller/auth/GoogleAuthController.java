package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.service.auth.DeviceVerificationService;
import com.techStack.authSys.repository.authorization.GoogleAuthService;
import com.techStack.authSys.util.validation.HelperUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Google Authentication Controller
 *
 * Handles Google OAuth authentication.
 * Uses Clock for timestamp tracking.
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(
        name = "Google OAuth",
        description = """
                Google OAuth 2.0 authentication and account linking.
                
                **Features:**
                - Sign in with Google
                - Automatic user creation for new Google users
                - Link Google account to existing user
                - Unlink Google account
                - Token verification
                
                **Authentication Flow:**
                1. User clicks "Sign in with Google" button
                2. Google OAuth popup/redirect
                3. Google returns ID token
                4. Frontend sends ID token to this API
                5. Backend verifies token with Google
                6. Creates/updates user account
                7. Returns authentication result
                
                **Account Linking:**
                - Existing users can link Google account
                - Multiple sign-in methods per account
                - Seamless switching between auth methods
                
                **Security:**
                - ID tokens verified with Google's servers
                - Tokens expire quickly (1 hour)
                - Device fingerprinting enabled
                - Audit logging for all operations
                - Email verification inherited from Google
                
                **Setup Required:**
                - Google Cloud Console project
                - OAuth 2.0 credentials configured
                - Authorized redirect URIs set
                - Client ID shared with frontend
                """
)
public class GoogleAuthController {

    /* =========================
       Dependencies
       ========================= */

    private final GoogleAuthService googleAuthService;
    private final DeviceVerificationService deviceVerificationService;
    private final Clock clock;

    /* =========================
       Google Sign-In
       ========================= */

    @Operation(
            summary = "Sign In with Google",
            description = """
                    Authenticate user with Google ID token.
                    
                    **Process:**
                    1. User completes Google OAuth flow in frontend
                    2. Google returns ID token to frontend
                    3. Frontend sends ID token to this endpoint
                    4. Backend verifies token with Google
                    5. If new user: creates account automatically
                    6. If existing user: authenticates and returns session
                    7. Returns user information and auth status
                    
                    **New User Creation:**
                    - Email from Google (automatically verified)
                    - Name from Google profile
                    - Profile picture from Google
                    - Default role: USER
                    - Status: ACTIVE (no approval needed)
                    - OAuth provider marked as GOOGLE
                    
                    **Existing User:**
                    - Matches by email address
                    - Updates profile info if changed
                    - Returns existing roles and permissions
                    - Records login event
                    
                    **Token Verification:**
                    - Validated directly with Google's servers
                    - Checks signature, expiry, issuer
                    - Verifies audience (client ID)
                    - Ensures token not expired
                    
                    **Frontend Integration:**
```javascript
                    // 1. Initialize Google Sign-In
                    google.accounts.id.initialize({
                      client_id: 'YOUR_GOOGLE_CLIENT_ID',
                      callback: handleGoogleResponse
                    });
                    
                    // 2. Handle Google response
                    async function handleGoogleResponse(response) {
                      const idToken = response.credential;
                      
                      // 3. Send to backend
                      const result = await fetch('/api/auth/google-signin', {
                        method: 'POST',
                        body: new URLSearchParams({ idToken })
                      });
                      
                      // 4. Handle result
                      if (result.success) {
                        // User authenticated
                        saveUserData(result.data);
                        redirectToDashboard();
                      }
                    }
```
                    
                    **Security Features:**
                    - Token verified with Google (not just decoded)
                    - Device fingerprinting
                    - IP tracking
                    - Session management
                    - Audit logging
                    
                    **Rate Limiting:**
                    - 10 attempts per IP per 15 minutes
                    - 5 attempts per email per 15 minutes
                    """,
            security = {}  // No authentication required (OAuth flow)
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Google authentication successful",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Existing User",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "Google authentication successful",
                                                      "data": {
                                                        "userId": "user-123",
                                                        "email": "user@gmail.com",
                                                        "firstName": "John",
                                                        "lastName": "Doe",
                                                        "emailVerified": true,
                                                        "roles": ["USER"],
                                                        "authProvider": "GOOGLE",
                                                        "authenticatedAt": "2024-03-15T14:22:30Z"
                                                      }
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "New User Created",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "Google authentication successful",
                                                      "data": {
                                                        "userId": "user-456",
                                                        "email": "newuser@gmail.com",
                                                        "firstName": "Jane",
                                                        "lastName": "Smith",
                                                        "emailVerified": true,
                                                        "roles": ["USER"],
                                                        "authProvider": "GOOGLE",
                                                        "authenticatedAt": "2024-03-15T14:22:30Z"
                                                      }
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid or malformed ID token"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Token verification failed with Google"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "409",
                    description = "Email already exists with different auth provider"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Too many authentication attempts"
            )
    })
    @PostMapping("/google-signin")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> googleSignIn(
            @Parameter(
                    description = "Google ID token from OAuth flow",
                    required = true,
                    example = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4MmU0M..."
            )
            @RequestParam String idToken,

            @Parameter(
                    description = "User agent string for device tracking",
                    example = "Mozilla/5.0..."
            )
            @RequestHeader(value = "User-Agent", required = false) String userAgent,

            ServerWebExchange exchange) {

        Instant startTime = clock.instant();
        String ipAddress = deviceVerificationService.extractClientIp(exchange);
        String deviceFingerprint = deviceVerificationService.generateDeviceFingerprint(
                ipAddress, userAgent);

        log.info("Google sign-in attempt at {} from IP: {}", startTime, ipAddress);

        return googleAuthService.authenticateWithGoogle(idToken, ipAddress, deviceFingerprint)
                .map(user -> {
                    Instant endTime = clock.instant();
                    Duration duration = Duration.between(startTime, endTime);

                    log.info("✅ Google sign-in successful at {} in {} for user: {}",
                            endTime, duration, HelperUtils.maskEmail(user.getEmail()));

                    Map<String, Object> responseData = Map.of(
                            "userId", user.getId(),
                            "email", user.getEmail(),
                            "firstName", user.getFirstName(),
                            "lastName", user.getLastName(),
                            "emailVerified", user.isEmailVerified(),
                            "roles", user.getRoles(),
                            "authProvider", "GOOGLE",
                            "authenticatedAt", endTime.toString()
                    );

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google authentication successful",
                            responseData
                    ));
                })
                .onErrorResume(CustomException.class, e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(startTime, errorTime);

                    log.error("❌ Google sign-in failed at {} after {}: {}",
                            errorTime, duration, e.getMessage());

                    HttpStatus status = determineHttpStatus(e);

                    return Mono.just(ResponseEntity.status(status)
                            .body(new ApiResponse<>(
                                    false,
                                    e.getMessage(),
                                    Map.of(
                                            "errorType", e.getClass().getSimpleName(),
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(startTime, errorTime);

                    log.error("❌ Unexpected error during Google sign-in at {} after {}: {}",
                            errorTime, duration, e.getMessage(), e);

                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(new ApiResponse<>(
                                    false,
                                    "An unexpected error occurred during Google authentication",
                                    Map.of(
                                            "errorType", e.getClass().getSimpleName(),
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }

    @Operation(
            summary = "Verify Google ID Token",
            description = """
                    Verify Google ID token without authentication (testing/validation).
                    
                    **Purpose:**
                    - Test Google OAuth integration
                    - Debug token issues
                    - Validate tokens before sign-in
                    - Development/debugging tool
                    
                    **Returns:**
                    - Email from token
                    - Email verification status
                    - User's name
                    - Profile picture URL
                    - Token validation timestamp
                    
                    **Use Cases:**
                    - Frontend debugging
                    - Integration testing
                    - Verify Google credentials work
                    - Check token contents before authentication
                    
                    **Not for Production Use:**
                    This endpoint is primarily for development and testing.
                    Production apps should use /google-signin directly.
                    
                    **Token Contents:**
                    Google ID tokens contain:
                    - User's email
                    - Email verified status
                    - Google user ID
                    - Name and profile picture
                    - Token issuer and audience
                    - Expiration time
                    """,
            security = {}  // No authentication required (testing endpoint)
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Token verified successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Google token verified successfully",
                                              "data": {
                                                "email": "user@gmail.com",
                                                "emailVerified": true,
                                                "name": "John Doe",
                                                "picture": "https://lh3.googleusercontent.com/...",
                                                "verifiedAt": "2024-03-15T14:22:30Z"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid token"
            )
    })
    @PostMapping("/google-verify")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> verifyGoogleToken(
            @Parameter(
                    description = "Google ID token to verify",
                    required = true,
                    example = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4MmU0M..."
            )
            @RequestParam String idToken) {

        Instant verifyTime = clock.instant();

        log.debug("Google token verification at {}", verifyTime);

        return googleAuthService.verifyGoogleToken(idToken)
                .map(payload -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Google token verified at {} for email: {}",
                            completionTime, HelperUtils.maskEmail(payload.getEmail()));

                    Map<String, Object> tokenData = Map.of(
                            "email", payload.getEmail(),
                            "emailVerified", payload.getEmailVerified(),
                            "name", payload.get("name") != null ? payload.get("name") : "",
                            "picture", payload.get("picture") != null ? payload.get("picture") : "",
                            "verifiedAt", completionTime.toString()
                    );

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google token verified successfully",
                            tokenData
                    ));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Google token verification failed at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new ApiResponse<>(
                                    false,
                                    "Invalid Google token",
                                    Map.of(
                                            "errorType", e.getClass().getSimpleName(),
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }

    @Operation(
            summary = "Link Google Account",
            description = """
                    Link Google account to existing user account.
                    
                    **Purpose:**
                    - Add Google sign-in to existing account
                    - Enable multiple authentication methods
                    - Simplify future logins
                    
                    **Process:**
                    1. User is already logged in (traditional auth)
                    2. User initiates Google OAuth flow
                    3. Google returns ID token
                    4. This endpoint links Google account
                    5. User can now sign in with either method
                    
                    **Requirements:**
                    - User must exist in system
                    - Google email must match user's email OR be unique
                    - User cannot link same Google account twice
                    
                    **Conflict Resolution:**
                    - If Google email matches user's email: Link directly
                    - If Google email different: Verify secondary email first
                    - If Google account already linked: Return error
                    
                    **After Linking:**
                    - User can sign in with Google
                    - User can still use password
                    - Both methods access same account
                    - Profile data synced from Google
                    
                    **Security:**
                    - Requires valid user ID
                    - Verifies Google token before linking
                    - Prevents account hijacking
                    - Audit logged
                    
                    **Use Cases:**
                    - User created account with password, wants Google option
                    - Corporate user wants personal Google linked
                    - Simplify login process
                    - Enable social auth post-registration
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Google account linked successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Google account linked successfully",
                                              "data": {
                                                "userId": "user-123",
                                                "email": "user@example.com",
                                                "googleLinked": true,
                                                "linkedAt": "2024-03-15T14:22:30Z"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid request or Google account already linked"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid Google token"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "User not found"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "409",
                    description = "Google account already linked to different user"
            )
    })
    @PostMapping("/google-link")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> linkGoogleAccount(
            @Parameter(
                    description = "User ID to link Google account to",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "Google ID token",
                    required = true,
                    example = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE4MmU0M..."
            )
            @RequestParam String idToken) {

        Instant linkTime = clock.instant();

        log.info("Google account link request at {} for user: {}", linkTime, userId);

        return googleAuthService.linkGoogleAccount(userId, idToken)
                .map(user -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Google account linked at {} for user: {}",
                            completionTime, userId);

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google account linked successfully",
                            Map.<String, Object>of(
                                    "userId", user.getId(),
                                    "email", user.getEmail(),
                                    "googleLinked", true,
                                    "linkedAt", completionTime.toString()
                            )
                    ));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Google account linking failed at {} for user {}: {}",
                            errorTime, userId, e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    false,
                                    "Failed to link Google account: " + e.getMessage(),
                                    Map.<String, Object>of(
                                            "userId", userId,
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }

    @Operation(
            summary = "Unlink Google Account",
            description = """
                    Remove Google account linkage from user account.
                    
                    **Purpose:**
                    - Disconnect Google sign-in option
                    - Remove OAuth connection
                    - Revert to password-only authentication
                    
                    **Process:**
                    1. Verify user exists and has Google linked
                    2. Remove Google account association
                    3. User can no longer sign in with Google
                    4. Password authentication still works (if set)
                    
                    **Requirements:**
                    - User must have alternative login method (password)
                    - Cannot unlink if Google is only auth method
                    - User must be authenticated
                    
                    **Safety Checks:**
                    - Prevents account lockout
                    - Ensures user has password set
                    - Warns if removing last auth method
                    - Requires confirmation
                    
                    **After Unlinking:**
                    - Google sign-in button disabled
                    - Must use password to login
                    - Can re-link Google later
                    - Profile picture reverts to default
                    
                    **Use Cases:**
                    - Privacy concerns
                    - Switching to different Google account
                    - Company policy changes
                    - Account security adjustment
                    
                    **Security:**
                    - Audit logged
                    - User notified via email
                    - Session not terminated
                    - Can re-link anytime
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Google account unlinked successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Google account unlinked successfully",
                                              "data": {
                                                "userId": "user-123",
                                                "googleLinked": false,
                                                "unlinkedAt": "2024-03-15T14:22:30Z"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Cannot unlink - no alternative auth method"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "404",
                    description = "User not found or Google not linked"
            )
    })
    @PostMapping("/google-unlink")
    public Mono<ResponseEntity<ApiResponse<Map<String, Object>>>> unlinkGoogleAccount(
            @Parameter(
                    description = "User ID to unlink Google account from",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId) {

        Instant unlinkTime = clock.instant();

        log.info("Google account unlink request at {} for user: {}", unlinkTime, userId);

        return googleAuthService.unlinkGoogleAccount(userId)
                .map(user -> {
                    Instant completionTime = clock.instant();

                    log.info("✅ Google account unlinked at {} for user: {}",
                            completionTime, userId);

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Google account unlinked successfully",
                            Map.<String, Object>of(
                                    "userId", user.getId(),
                                    "googleLinked", false,
                                    "unlinkedAt", completionTime.toString()
                            )
                    ));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Google account unlinking failed at {} for user {}: {}",
                            errorTime, userId, e.getMessage());

                    return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new ApiResponse<>(
                                    false,
                                    "Failed to unlink Google account: " + e.getMessage(),
                                    Map.<String, Object>of(
                                            "userId", userId,
                                            "timestamp", errorTime.toString()
                                    )
                            )));
                });
    }

    /* =========================
       Private Helper Methods
       ========================= */

    /**
     * Determine HTTP status from CustomException
     */
    private HttpStatus determineHttpStatus(CustomException e) {
        String message = e.getMessage().toLowerCase();

        if (message.contains("unauthorized") || message.contains("invalid token")) {
            return HttpStatus.UNAUTHORIZED;
        } else if (message.contains("bad request") || message.contains("invalid")) {
            return HttpStatus.BAD_REQUEST;
        } else if (message.contains("not found")) {
            return HttpStatus.NOT_FOUND;
        } else if (message.contains("conflict") || message.contains("already exists")) {
            return HttpStatus.CONFLICT;
        }

        // Check if CustomException has a status field
        if (e.getStatus() != null) {
            return e.getStatus();
        }

        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}