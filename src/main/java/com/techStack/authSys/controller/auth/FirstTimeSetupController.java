package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.request.ChangePasswordRequest;
import com.techStack.authSys.dto.request.VerifyOtpRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.dto.response.PasswordChangeResult;
import com.techStack.authSys.models.auth.TokenPair;
import com.techStack.authSys.service.auth.FirstTimeLoginSetupService;
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
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

/**
 * First-Time Setup Controller
 *
 * Handles password change and OTP verification for new users.
 *
 * Flow:
 * 1. Login with temporary password → get temporary token
 * 2. POST /change-password → OTP sent
 * 3. POST /verify-otp → full access granted
 */
@Slf4j
@RestController
@RequestMapping("/api/auth/first-time-setup")
@RequiredArgsConstructor
@Tag(
        name = "First-Time Setup",
        description = """
                First-time user setup flow with password change and OTP verification.
                
                **Prerequisites:**
                - User must have `forcePasswordChange = true`
                - User must have logged in and received temporary token
                
                **Flow:**
                1. Change password (this endpoint sends OTP)
                2. Verify OTP received on phone
                3. Get full access tokens
                
                **Security:**
                - Temporary token scope: FIRST_TIME_SETUP
                - Temporary token expiry: 30 minutes
                - OTP validity: 10 minutes
                - Max OTP attempts: 3
                """
)
public class FirstTimeSetupController {

    private final FirstTimeLoginSetupService firstTimeSetupService;
    private final Clock clock;

    /* =========================
       Step 1 — Change Password
       ========================= */

    @Operation(
            summary = "Change Password (Step 1/2)",
            description = """
                    Change temporary password and receive OTP on phone.
                    
                    **Requirements:**
                    - Valid temporary token (from login response)
                    - Password must meet complexity requirements
                    
                    **After Success:**
                    - OTP sent to registered phone number
                    - OTP valid for 10 minutes
                    - Proceed to verify-otp endpoint
                    
                    **Rate Limiting:**
                    - 5 OTP requests per 15 minutes
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password changed successfully, OTP sent",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Password changed successfully. OTP sent to your phone. Valid for 10 minutes.",
                                              "data": null
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "207",
                    description = "Password changed but OTP sending failed",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Password changed but failed to send OTP. Please try resending.",
                                              "data": null
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid request or user not in first-time setup",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "User is not in first-time setup state",
                                              "errorCode": "INVALID_STATE"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired temporary token"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Rate limit exceeded"
            )
    })
    @PostMapping("/change-password")
    public Mono<ResponseEntity<ApiResponse<Void>>> changePassword(
            @Parameter(
                    description = "Temporary token from login",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzUxMiJ9..."
            )
            @RequestHeader("Authorization") String tempToken,

            @Parameter(
                    description = "New password details",
                    required = true,
                    schema = @Schema(implementation = ChangePasswordRequest.class),
                    example = """
                        {
                          "newPassword": "NewSecurePass123!@"
                        }
                        """
            )
            @Valid @RequestBody ChangePasswordRequest request) {

        Instant now = clock.instant();
        log.info("🔑 Password change request for first-time user at {}", now);

        return firstTimeSetupService.changePasswordFirstTime(tempToken, request)
                .map(result -> {
                    if (!result.otpSent()) {
                        // Use ApiResponse.error() factory method which returns ApiResponse<Void>
                        return ResponseEntity.status(HttpStatus.MULTI_STATUS)
                                .body(ApiResponse.error(result.message()));
                    }

                    // Use ApiResponse.success() factory method which returns ApiResponse<Void>
                    return ResponseEntity.ok(ApiResponse.success(result.message()));
                })
                .doOnSuccess(response ->
                        log.info("✅ Password change completed at {}", clock.instant()))
                .doOnError(e ->
                        log.error("❌ Password change failed at {}: {}",
                                clock.instant(), e.getMessage()));
    }

    /* =========================
       Step 2 — Verify OTP
       ========================= */

    @Operation(
            summary = "Verify OTP (Step 2/2)",
            description = """
                    Verify OTP received on phone and complete first-time setup.
                    
                    **Requirements:**
                    - Valid temporary token (same as used in change-password)
                    - 6-digit OTP received via SMS
                    
                    **After Success:**
                    - `forcePasswordChange` set to false
                    - `phoneVerified` set to true
                    - Full access tokens returned
                    - Can now access all authenticated endpoints
                    
                    **Attempts:**
                    - Maximum 3 attempts per OTP
                    - After 3 failed attempts, must request new OTP
                    
                    **Expiry:**
                    - OTP valid for 10 minutes
                    - Request new OTP if expired
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "OTP verified, setup complete",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Setup complete! You can now access your account.",
                                              "data": {
                                                "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
                                                "refreshToken": "eyJhbGciOiJIUzUxMiJ9..."
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid OTP, expired, or attempts exceeded",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Invalid OTP",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "Invalid OTP",
                                                      "errorCode": "INVALID_OTP"
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "OTP Expired",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "OTP has expired",
                                                      "errorCode": "OTP_EXPIRED"
                                                    }
                                                    """
                                    )
                            }
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired temporary token"
            )
    })
    @PostMapping("/verify-otp")
    public Mono<ResponseEntity<ApiResponse<Map<String, String>>>> verifyOtpAndComplete(
            @Parameter(
                    description = "Temporary token from login",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzUxMiJ9..."
            )
            @RequestHeader("Authorization") String tempToken,

            @Parameter(
                    description = "OTP received on phone",
                    required = true,
                    schema = @Schema(implementation = VerifyOtpRequest.class),
                    example = """
                            {
                              "otp": "123456"
                            }
                            """
            )
            @Valid @RequestBody VerifyOtpRequest request) {

        Instant now = clock.instant();
        log.info("📱 OTP verification for first-time user at {}", now);

        return firstTimeSetupService.verifyOtpAndCompleteSetup(tempToken, request)
                .map(tokenPair -> {
                    Map<String, String> tokens = Map.of(
                            "accessToken", tokenPair.getAccessToken(),
                            "refreshToken", tokenPair.getRefreshToken()
                    );

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            "Setup complete! You can now access your account.",
                            tokens
                    ));
                })
                .doOnSuccess(response ->
                        log.info("✅ First-time setup completed at {}", clock.instant()))
                .doOnError(e ->
                        log.error("❌ OTP verification failed at {}: {}",
                                clock.instant(), e.getMessage()));
    }

    /* =========================
       Resend OTP (Optional)
       ========================= */

    @Operation(
            summary = "Resend OTP",
            description = """
                    Resend OTP if user didn't receive it or it expired.
                    
                    **Use Cases:**
                    - SMS not received
                    - OTP expired (10 minutes)
                    - User entered incorrect number 3 times
                    
                    **Rate Limiting:**
                    - 5 OTP requests per 15 minutes
                    
                    **After Success:**
                    - New OTP sent to phone
                    - Previous OTP invalidated
                    - 3 new attempts available
                    """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "OTP resent successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "OTP sent successfully. Valid for 10 minutes.",
                                              "data": null
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Rate limit exceeded",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": false,
                                              "message": "Too many OTP requests. Please try again in 15 minutes.",
                                              "errorCode": "RATE_LIMIT_EXCEEDED"
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired temporary token"
            )
    })
    @PostMapping("/resend-otp")
    public Mono<ResponseEntity<ApiResponse<Void>>> resendOtp(
            @Parameter(
                    description = "Temporary token from login",
                    required = true,
                    example = "Bearer eyJhbGciOiJIUzUxMiJ9..."
            )
            @RequestHeader("Authorization") String tempToken) {

        Instant now = clock.instant();
        log.info("🔄 OTP resend request at {}", now);

        return firstTimeSetupService.resendOtp(tempToken)
                .map(result -> {
                    if (result.isRateLimited()) {
                        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                .body(ApiResponse.error(result.getMessage(), "RATE_LIMIT_EXCEEDED"));
                    }

                    if (!result.isSent()) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.error(result.getMessage(), "OTP_SEND_FAILED"));
                    }

                    return ResponseEntity.ok(ApiResponse.success(result.getMessage()));
                })
                .doOnSuccess(response ->
                        log.info("✅ OTP resent at {}", clock.instant()))
                .doOnError(e ->
                        log.error("❌ OTP resend failed at {}: {}",
                                clock.instant(), e.getMessage()));
    }
}