package com.techStack.authSys.controller.user;

import com.techStack.authSys.dto.request.ForcePasswordChangeRequest;
import com.techStack.authSys.dto.request.PasswordChangeRequest;
import com.techStack.authSys.dto.request.PasswordResetCompleteRequest;
import com.techStack.authSys.dto.request.PasswordResetRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.service.user.PasswordChangeService;
import com.techStack.authSys.service.user.PasswordResetService;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Password Management Controller
 *
 * Handles all password-related operations including user-initiated changes,
 * admin-forced changes, and password reset flows with Clock-based tracking.
 *
 * @version 1.0
 * @since 2026-02-14
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/password")
@RequiredArgsConstructor
@Tag(
        name = "Password Management",
        description = "APIs for password operations including user-initiated changes, " +
                "admin-forced changes, and password reset workflows. " +
                "Implements secure password handling with validation, history tracking, and notification."
)
public class PasswordManagementController {

    /* =========================
       Dependencies
       ========================= */

    private final PasswordChangeService passwordChangeService;
    private final PasswordResetService passwordResetService;
    private final Clock clock;

    /* =========================
       User Password Change
       ========================= */

    /**
     * Change password (user-initiated)
     */
    @PostMapping(value = "/change",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Change password",
            description = """
            Allows authenticated users to change their password.
            
            **Requirements:**
            - User must be authenticated
            - Current password must be correct
            - New password must be different from current password
            - New password and confirmation must match
            - New password must meet strength requirements
            
            **Password Strength Requirements:**
            - Minimum 8 characters
            - At least one uppercase letter
            - At least one lowercase letter
            - At least one number
            - At least one special character (!@#$%^&*)
            
            **Security Features:**
            - Password history check (last 5 passwords)
            - Audit logging of all password changes
            - Automatic session invalidation after change
            """,
            tags = {"Password Management"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password changed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ApiResponse.class),
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "message": "Password changed successfully",
                          "timestamp": "2026-02-14T10:30:00Z",
                          "timestampMillis": 1707910200000
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Bad Request - Validation failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Passwords don't match",
                                            value = """
                            {
                              "success": false,
                              "message": "New password and confirmation do not match",
                              "timestamp": "2026-02-14T10:30:00Z"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Same password",
                                            value = """
                            {
                              "success": false,
                              "message": "New password must be different from current password",
                              "timestamp": "2026-02-14T10:30:00Z"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Weak password",
                                            value = """
                            {
                              "success": false,
                              "message": "Password does not meet strength requirements",
                              "timestamp": "2026-02-14T10:30:00Z"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Password in history",
                                            value = """
                            {
                              "success": false,
                              "message": "Password was recently used. Please choose a different password.",
                              "timestamp": "2026-02-14T10:30:00Z"
                            }
                            """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized - Invalid or missing authentication token",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Unauthorized access",
                          "errorCode": "UNAUTHORIZED"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Internal Server Error",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Failed to change password. Please try again.",
                          "timestamp": "2026-02-14T10:30:00Z"
                        }
                        """
                            )
                    )
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Password change request",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = PasswordChangeRequest.class),
                    examples = @ExampleObject(
                            name = "Password change request",
                            value = """
                    {
                      "currentPassword": "OldPass123!",
                      "newPassword": "NewSecurePass456!",
                      "confirmPassword": "NewSecurePass456!"
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<ApiResponse<Void>>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(hidden = true) ServerWebExchange exchange) {

        Instant changeTime = clock.instant();
        String email = userDetails.getUsername();

        log.info("Password change initiated at {} for user: {}",
                changeTime, HelperUtils.maskEmail(email));

        // Validate passwords match
        if (!request.passwordsMatch()) {
            Instant errorTime = clock.instant();
            log.warn("Password confirmation mismatch at {} for: {}",
                    errorTime, HelperUtils.maskEmail(email));

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password and confirmation do not match",
                            errorTime
                    )));
        }

        // Validate passwords are different
        if (!request.passwordsAreDifferent()) {
            Instant errorTime = clock.instant();
            log.warn("Same password attempt at {} for: {}",
                    errorTime, HelperUtils.maskEmail(email));

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password must be different from current password",
                            errorTime
                    )));
        }

        return passwordChangeService.changePassword(
                        email,
                        request.getCurrentPassword(),
                        request.getNewPassword()
                )
                .map(user -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(changeTime, completionTime);

                    log.info("✅ Password changed successfully at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(email));

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password changed successfully",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(IllegalArgumentException.class, e -> {
                    Instant errorTime = clock.instant();
                    log.warn("Invalid password change request at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(ApiResponse.error(e.getMessage(), errorTime)));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Password change failed at {}: {}", errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(ApiResponse.error(
                                    "Failed to change password. Please try again.",
                                    errorTime
                            )));
                });
    }

    /* =========================
       Admin Force Password Change
       ========================= */

    /**
     * Force password change (admin-initiated)
     */
    @PostMapping(value = "/force-change",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    @Operation(
            summary = "Force password change (Admin only)",
            description = """
            Allows administrators to forcibly change a user's password.
            
            **Use Cases:**
            - Security breach recovery
            - Account compromise response
            - Compliance requirements
            - User assistance
            
            **Features:**
            - Optional user notification via email
            - Can require password change on next login
            - Audit logging with admin identity and reason
            - Password strength validation
            
            **Security:**
            - Requires ADMIN or SUPER_ADMIN role
            - All actions are logged for audit
            - User receives notification (if enabled)
            - Session invalidation optional
            
            **Required Role:** ADMIN or SUPER_ADMIN
            """,
            tags = {"Password Management"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password changed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "message": "Password changed successfully. User will be notified.",
                          "timestamp": "2026-02-14T10:30:00Z"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Bad Request - Validation failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "New password and confirmation do not match",
                          "timestamp": "2026-02-14T10:30:00Z"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "403",
                    description = "Forbidden - User lacks required role",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": false,
                          "message": "Access denied",
                          "errorCode": "FORBIDDEN"
                        }
                        """
                            )
                    )
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Force password change request",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ForcePasswordChangeRequest.class),
                    examples = @ExampleObject(
                            name = "Force change request",
                            value = """
                    {
                      "userId": "user-123",
                      "newPassword": "TempSecurePass789!",
                      "confirmPassword": "TempSecurePass789!",
                      "reason": "Security breach - compromised credentials",
                      "sendNotification": true,
                      "requireChangeOnNextLogin": true
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<ApiResponse<Void>>> forcePasswordChange(
            @Valid @RequestBody ForcePasswordChangeRequest request,
            @Parameter(hidden = true) @AuthenticationPrincipal UserDetails adminDetails) {

        Instant forceTime = clock.instant();
        String adminEmail = adminDetails.getUsername();

        log.warn("🔐 Forced password change initiated at {} by admin: {} for user: {}",
                forceTime,
                HelperUtils.maskEmail(adminEmail),
                request.getUserId());

        // Validate passwords match
        if (!request.passwordsMatch()) {
            Instant errorTime = clock.instant();
            log.warn("Password confirmation mismatch at {}", errorTime);

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password and confirmation do not match",
                            errorTime
                    )));
        }

        return passwordChangeService.forcePasswordChange(
                        request.getUserId(),
                        request.getNewPassword(),
                        request.getReason(),
                        adminEmail,
                        request.isSendNotification(),
                        request.isRequireChangeOnNextLogin()
                )
                .map(user -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(forceTime, completionTime);

                    log.warn("✅ Forced password change completed at {} in {} for user: {} by admin: {}",
                            completionTime,
                            duration,
                            request.getUserId(),
                            HelperUtils.maskEmail(adminEmail));

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password changed successfully. User will be notified.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Forced password change failed at {}: {}", errorTime, e.getMessage(), e);

                    return Mono.just(ResponseEntity
                            .internalServerError()
                            .body(ApiResponse.error(
                                    "Failed to change password. Please try again.",
                                    errorTime
                            )));
                });
    }

    /* =========================
       Password Reset Flow
       ========================= */

    /**
     * Initiate password reset
     */
    @PostMapping(value = "/reset/initiate",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Initiate password reset",
            description = """
            Initiates the password reset process for a user account.
            
            **Flow:**
            1. User submits email address
            2. System generates secure reset token (valid for 1 hour)
            3. Email sent with reset link containing token
            4. User clicks link and completes reset with new password
            
            **Security Features:**
            - No user enumeration (same response for existing/non-existing emails)
            - Token expires after 1 hour
            - One-time use token
            - Rate limited (5 requests per hour per IP)
            - Secure token generation (cryptographically random)
            
            **Note:** For security, this endpoint always returns success,
            even if the email doesn't exist in the system.
            """,
            tags = {"Password Management"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Reset email sent (or would be sent if account exists)",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "message": "If an account exists with this email, you will receive a password reset link.",
                          "timestamp": "2026-02-14T10:30:00Z"
                        }
                        """
                            )
                    )
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Password reset initiation request",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = PasswordResetRequest.class),
                    examples = @ExampleObject(
                            name = "Reset request",
                            value = """
                    {
                      "email": "user@example.com"
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<ApiResponse<Void>>> initiatePasswordReset(
            @Valid @RequestBody PasswordResetRequest request) {

        Instant initiateTime = clock.instant();

        log.info("Password reset initiated at {} for: {}",
                initiateTime, HelperUtils.maskEmail(request.getEmail()));

        return passwordResetService.initiatePasswordReset(request.getEmail())
                .map(token -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(initiateTime, completionTime);

                    log.info("✅ Password reset email sent at {} in {}",
                            completionTime, duration);

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "If an account exists with this email, you will receive a password reset link.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    // Don't reveal if user exists - security best practice
                    log.warn("Password reset process completed at {} (may have failed internally)",
                            errorTime);

                    return Mono.just(ResponseEntity.ok(
                            ApiResponse.success(
                                    "If an account exists with this email, you will receive a password reset link.",
                                    errorTime
                            )
                    ));
                });
    }

    /**
     * Complete password reset
     */
    @PostMapping(value = "/reset/complete",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Complete password reset",
            description = """
            Completes the password reset process with a valid reset token.
            
            **Process:**
            1. User receives reset token via email
            2. User submits token with new password
            3. System validates token (not expired, not used)
            4. Password is updated
            5. Token is invalidated
            6. All user sessions are terminated
            
            **Token Requirements:**
            - Must not be expired (1 hour validity)
            - Must not have been previously used
            - Must match a valid user account
            
            **Password Requirements:**
            - Minimum 8 characters
            - At least one uppercase letter
            - At least one lowercase letter
            - At least one number
            - At least one special character
            - Cannot match last 5 passwords
            
            **After Reset:**
            - All existing sessions are invalidated
            - User must login with new password
            - Password change is logged for audit
            """,
            tags = {"Password Management"}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password reset successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    name = "Success response",
                                    value = """
                        {
                          "success": true,
                          "message": "Password reset successful. You can now login with your new password.",
                          "timestamp": "2026-02-14T10:30:00Z"
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Bad Request - Invalid token or validation failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Invalid token",
                                            value = """
                            {
                              "success": false,
                              "message": "Invalid or expired reset token. Please request a new password reset.",
                              "timestamp": "2026-02-14T10:30:00Z"
                            }
                            """
                                    ),
                                    @ExampleObject(
                                            name = "Passwords don't match",
                                            value = """
                            {
                              "success": false,
                              "message": "New password and confirmation do not match",
                              "timestamp": "2026-02-14T10:30:00Z"
                            }
                            """
                                    )
                            }
                    )
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Password reset completion request",
            required = true,
            content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = PasswordResetCompleteRequest.class),
                    examples = @ExampleObject(
                            name = "Complete reset request",
                            value = """
                    {
                      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                      "newPassword": "NewSecurePass123!",
                      "confirmPassword": "NewSecurePass123!"
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<ApiResponse<Void>>> completePasswordReset(
            @Valid @RequestBody PasswordResetCompleteRequest request) {

        Instant resetTime = clock.instant();

        log.info("Password reset completion initiated at {}", resetTime);

        // Validate passwords match
        if (!request.passwordsMatch()) {
            Instant errorTime = clock.instant();
            log.warn("Password confirmation mismatch at {}", errorTime);

            return Mono.just(ResponseEntity
                    .badRequest()
                    .body(ApiResponse.error(
                            "New password and confirmation do not match",
                            errorTime
                    )));
        }

        return passwordResetService.resetPassword(
                        request.getToken(),
                        request.getNewPassword()
                )
                .map(user -> {
                    Instant completionTime = clock.instant();
                    Duration duration = Duration.between(resetTime, completionTime);

                    log.info("✅ Password reset completed at {} in {} for: {}",
                            completionTime, duration, HelperUtils.maskEmail(user.getEmail()));

                    return ResponseEntity.ok(
                            ApiResponse.success(
                                    "Password reset successful. You can now login with your new password.",
                                    completionTime
                            )
                    );
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Password reset failed at {}: {}", errorTime, e.getMessage());

                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(ApiResponse.error(
                                    "Invalid or expired reset token. Please request a new password reset.",
                                    errorTime
                            )));
                });
    }
}