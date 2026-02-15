package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.internal.TokenValidationRequest;
import com.techStack.authSys.dto.request.PasswordResetCompleteRequest;
import com.techStack.authSys.dto.request.PasswordResetRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.email.EmailSendingException;
import com.techStack.authSys.service.user.PasswordResetService;
import com.techStack.authSys.util.validation.HelperUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Password Reset Controller
 *
 * Handles password reset workflows.
 * Uses Clock for timestamp tracking and duration metrics.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/password-reset")
@RequiredArgsConstructor
@Tag(
        name = "Password Reset",
        description = """
                Self-service password reset workflow.
                
                **Features:**
                - Secure password reset via email
                - Token-based authentication
                - Time-limited reset links
                - Protection against user enumeration
                - Rate limiting to prevent abuse
                
                **Process:**
                1. User requests password reset with email
                2. System sends reset link to email (if user exists)
                3. User clicks link with token
                4. Frontend validates token
                5. User enters new password
                6. System updates password and invalidates token
                
                **Security:**
                - Reset tokens expire in 1 hour
                - Single use tokens (invalidated after use)
                - No user enumeration (same response for existing/non-existing users)
                - Rate limited to prevent abuse
                - Password complexity validation
                - Secure token generation (cryptographically random)
                
                **No Authentication Required:**
                All endpoints are public for password recovery.
                """
)
public class PasswordResetController {

    /* =========================
       Dependencies
       ========================= */

    private final PasswordResetService passwordResetService;
    private final Clock clock;

    /* =========================
       Password Reset Operations
       ========================= */

    @Operation(
            summary = "Initiate Password Reset",
            description = """
                    Request a password reset link via email.
                    
                    **Process:**
                    1. User submits email address
                    2. System checks if user exists
                    3. If exists: generates secure token + sends email
                    4. If not exists: responds successfully (no user enumeration)
                    5. Token expires in 1 hour
                    
                    **Email Contains:**
                    - Password reset link with token
                    - Expiry time (1 hour)
                    - Security notice
                    - Instructions to ignore if not requested
                    
                    **Security Features:**
                    - **No User Enumeration**: Same response whether user exists or not
                    - **Rate Limited**: Max 3 requests per hour per email
                    - **Token Expiry**: Links expire in 1 hour
                    - **Single Use**: Token invalidated after successful reset
                    - **Secure Generation**: Cryptographically random tokens
                    
                    **Use Cases:**
                    - User forgot password
                    - User locked out of account
                    - Security-conscious user wants to change password
                    - Compromised account recovery
                    
                    **Rate Limiting:**
                    - 3 requests per email per hour
                    - 10 requests per IP per hour
                    - Returns 429 if exceeded
                    
                    **Client Handling:**
```javascript
                    // Always show success message to prevent user enumeration
                    if (response.success) {
                      showMessage("Check your email for reset link");
                    }
```
                    """,
            security = {}  // No authentication required
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Reset email sent (or would be sent if user exists)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Success",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "Password reset email sent. Please check your inbox.",
                                                      "timestamp": "2024-03-15T14:22:30Z",
                                                      "timestampMillis": 1710512550000
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "User Not Found (Same Response)",
                                            description = "Returns same response to prevent user enumeration",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "message": "If an account exists with this email, you will receive a password reset link.",
                                                      "timestamp": "2024-03-15T14:22:30Z",
                                                      "timestampMillis": 1710512550000
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid email format",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Invalid email format",
                                              "timestamp": "2024-03-15T14:22:30Z",
                                              "timestampMillis": 1710512550000
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Too many reset requests",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Too many password reset requests. Please try again in 1 hour.",
                                              "timestamp": "2024-03-15T14:22:30Z",
                                              "timestampMillis": 1710512550000
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "503",
                    description = "Email service unavailable",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Failed to send reset email. Please try again later.",
                                              "timestamp": "2024-03-15T14:22:30Z",
                                              "timestampMillis": 1710512550000
                                            }
                                            """
                            )
                    )
            )
    })
    @PostMapping("/initiate")
    public Mono<ResponseEntity<Map<String, Object>>> initiatePasswordReset(
            @Parameter(
                    description = "Password reset request with email",
                    required = true,
                    schema = @Schema(implementation = PasswordResetRequest.class),
                    example = """
                            {
                              "email": "user@example.com"
                            }
                            """
            )
            @Valid @RequestBody PasswordResetRequest request) {

        Instant initiateTime = clock.instant();

        log.info("Password reset initiated at {} for email: {}",
                initiateTime, HelperUtils.maskEmail(request.getEmail()));

        return passwordResetService.initiatePasswordReset(request.getEmail())
                .map(token -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(initiateTime, completionTime);

                    log.info("✅ Password reset email sent at {} in {} to: {}",
                            completionTime,
                            duration,
                            HelperUtils.maskEmail(request.getEmail()));

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "success", true,
                            "message", "Password reset email sent. Please check your inbox.",
                            "timestamp", completionTime.toString(),
                            "timestampMillis", completionTime.toEpochMilli()
                    ));
                })
                .onErrorResume(IllegalArgumentException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.warn("Invalid password reset request at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "message", e.getMessage(),
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                })
                .onErrorResume(UserNotFoundException.class, e -> {
                    Instant errorTime = clock.instant();

                    // Don't reveal whether user exists - security best practice
                    log.warn("Password reset attempted for non-existent user at {}", errorTime);

                    return Mono.just(ResponseEntity
                            .ok()
                            .body(Map.<String, Object>of(
                                    "success", true,
                                    "message", "If an account exists with this email, you will receive a password reset link.",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                })
                .onErrorResume(EmailSendingException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Email sending failed at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .status(HttpStatus.SERVICE_UNAVAILABLE)
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "message", "Failed to send reset email. Please try again later.",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Unexpected error at {}: {}", errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "message", "An unexpected error occurred. Please try again.",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                });
    }

    @Operation(
            summary = "Validate Reset Token",
            description = """
                    Validate a password reset token before allowing password change.
                    
                    **Purpose:**
                    - Check if token is valid before showing password form
                    - Provide better UX with early validation
                    - Prevent unnecessary password entry attempts
                    
                    **Token Validation Checks:**
                    - Token exists in database
                    - Token not expired (< 1 hour old)
                    - Token not already used
                    - Associated user still exists
                    - User account not disabled/locked
                    
                    **Token States:**
                    - **Valid**: Token can be used for password reset
                    - **Expired**: Token older than 1 hour
                    - **Used**: Token already consumed
                    - **Invalid**: Token doesn't exist or malformed
                    
                    **Frontend Flow:**
```javascript
                    // 1. Extract token from URL
                    const token = new URLSearchParams(window.location.search).get('token');
                    
                    // 2. Validate token
                    const response = await validateToken(token);
                    
                    // 3. Show appropriate UI
                    if (response.valid) {
                      showPasswordResetForm();
                    } else {
                      showErrorMessage("Link expired or invalid. Request new reset.");
                    }
```
                    
                    **Use Cases:**
                    - User clicks reset link in email
                    - Frontend validates before showing form
                    - User bookmarked reset page and returns later
                    - Token expired, need to request new one
                    
                    **No Rate Limiting:**
                    This endpoint is not rate limited as it only validates,
                    doesn't perform sensitive operations.
                    """,
            security = {}  // No authentication required
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Token validation result",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Valid Token",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "valid": true,
                                                      "message": "Token is valid",
                                                      "timestamp": "2024-03-15T14:22:30Z",
                                                      "timestampMillis": 1710512550000
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Invalid Token",
                                            value = """
                                                    {
                                                      "success": true,
                                                      "valid": false,
                                                      "message": "Token is invalid or expired",
                                                      "timestamp": "2024-03-15T14:22:30Z",
                                                      "timestampMillis": 1710512550000
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Malformed token"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Validation error"
            )
    })
    @PostMapping("/validate-token")
    public Mono<ResponseEntity<Map<String, Object>>> validateResetToken(
            @Parameter(
                    description = "Token validation request",
                    required = true,
                    schema = @Schema(implementation = TokenValidationRequest.class),
                    example = """
                            {
                              "token": "eyJhbGciOiJIUzUxMiJ9..."
                            }
                            """
            )
            @Valid @RequestBody TokenValidationRequest request) {

        Instant validationTime = clock.instant();

        log.debug("Token validation request at {}", validationTime);

        return passwordResetService.validateResetToken(request.getToken())
                .map(valid -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(validationTime, completionTime);

                    log.info("✅ Token validation completed at {} in {} - Valid: {}",
                            completionTime, duration, valid);

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "success", true,
                            "valid", valid,
                            "message", valid ? "Token is valid" : "Token is invalid or expired",
                            "timestamp", completionTime.toString(),
                            "timestampMillis", completionTime.toEpochMilli()
                    ));
                })
                .defaultIfEmpty(ResponseEntity
                        .badRequest()
                        .body(Map.<String, Object>of(
                                "success", false,
                                "valid", false,
                                "message", "Token is invalid or expired",
                                "timestamp", clock.instant().toString(),
                                "timestampMillis", clock.instant().toEpochMilli()
                        )))
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Token validation error at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(Map.<String, Object>of(
                                    "success", false,
                                    "valid", false,
                                    "message", "An error occurred during validation",
                                    "timestamp", errorTime.toString(),
                                    "timestampMillis", errorTime.toEpochMilli()
                            )));
                });
    }

    @Operation(
            summary = "Complete Password Reset",
            description = """
                    Complete password reset with new password.
                    
                    **Process:**
                    1. User submits token + new password
                    2. System validates token (must be valid and not expired)
                    3. System validates password complexity
                    4. System checks password not in history (last 5)
                    5. System hashes and saves new password
                    6. System invalidates reset token
                    7. System sends confirmation email
                    
                    **Password Requirements:**
                    - Minimum 8 characters
                    - At least one uppercase letter
                    - At least one lowercase letter
                    - At least one number
                    - At least one special character (!@#$%^&*...)
                    - Not in common password dictionary
                    - Not same as last 5 passwords
                    
                    **Security Measures:**
                    - Token validated before password check
                    - Password hashed with BCrypt
                    - Token invalidated after use (prevents replay)
                    - All user sessions terminated
                    - Password change logged in audit trail
                    - Confirmation email sent
                    
                    **After Success:**
                    - User can immediately login with new password
                    - Old password no longer works
                    - Reset token becomes invalid
                    - User receives confirmation email
                    
                    **Error Cases:**
                    - **Invalid Token**: Token expired/used/doesn't exist
                    - **Weak Password**: Doesn't meet complexity requirements
                    - **Reused Password**: Same as recent password
                    - **Common Password**: In dictionary of common passwords
                    
                    **Frontend Flow:**
```javascript
                    // 1. Get token from URL
                    const token = getTokenFromUrl();
                    
                    // 2. Get new password from form
                    const newPassword = form.password.value;
                    
                    // 3. Submit reset
                    const response = await completeReset(token, newPassword);
                    
                    // 4. Handle response
                    if (response.success) {
                      showSuccess("Password reset successful!");
                      redirectToLogin();
                    } else {
                      showError(response.message);
                    }
```
                    
                    **Rate Limiting:**
                    - 5 attempts per token
                    - After 5 failures, token invalidated
                    - User must request new reset
                    """,
            security = {}  // No authentication required (token-based)
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset successful",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiResponse.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Password reset successful. You can now login with your new password.",
                                              "data": null,
                                              "timestamp": "2024-03-15T14:22:30Z"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid token or weak password",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Invalid Token",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "Reset token is invalid or has expired",
                                                      "data": null,
                                                      "timestamp": "2024-03-15T14:22:30Z"
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Weak Password",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "Password must contain at least one uppercase letter",
                                                      "data": null,
                                                      "timestamp": "2024-03-15T14:22:30Z"
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Password Reused",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "Password has been used recently. Please choose a different password.",
                                                      "data": null,
                                                      "timestamp": "2024-03-15T14:22:30Z"
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Server error during password reset"
            )
    })
    @PostMapping("/complete")
    public Mono<ResponseEntity<ApiResponse<Void>>> completePasswordReset(
            @Parameter(
                    description = "Password reset completion request",
                    required = true,
                    schema = @Schema(implementation = PasswordResetCompleteRequest.class),
                    example = """
                            {
                              "token": "eyJhbGciOiJIUzUxMiJ9...",
                              "newPassword": "NewSecurePass123!@"
                            }
                            """
            )
            @Valid @RequestBody PasswordResetCompleteRequest request) {

        Instant resetTime = clock.instant();

        log.info("Password reset completion initiated at {}", resetTime);

        return passwordResetService.resetPassword(
                        request.getToken(),
                        request.getNewPassword()
                )
                .map(success -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(resetTime, completionTime);

                    log.info("✅ Password reset completed at {} in {}",
                            completionTime, duration);

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password reset successful. You can now login with your new password.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(IllegalArgumentException.class, e -> {
                    Instant errorTime = clock.instant();

                    log.warn("Invalid password reset completion at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(ApiResponse.error(e.getMessage(), errorTime)));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Password reset failed at {}: {}",
                            errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(ApiResponse.error(
                                    "Failed to reset password. Please try again.",
                                    errorTime
                            )));
                });
    }
}