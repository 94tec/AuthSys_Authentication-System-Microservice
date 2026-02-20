package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.request.ChangePasswordRequest;
import com.techStack.authSys.dto.request.CompleteSetupRequest;
import com.techStack.authSys.dto.request.VerifyOtpRequest;
import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.exception.auth.AuthException;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * First-Time Setup Controller - Following FirstTimeLoginSetupService Pattern
 *
 * OPTIMIZED 3-STEP FLOW:
 * ======================
 * STEP 1: POST /change-password
 *   → Validate & STAGE password in Redis (NOT in DB)
 *   → Lock temp password
 *   → Send OTP
 *
 * STEP 2: POST /verify-otp
 *   → Verify OTP
 *   → Generate verificationToken (5-min, single-use)
 *   → Return verificationToken
 *
 * STEP 3: POST /complete
 *   → Validate verificationToken
 *   → COMMIT staged password to DB (FIRST TIME!)
 *   → Activate account
 *   → Invalidate sessions
 *   → Return full tokens
 *
 * @version 5.0 - Production Ready
 */
@Slf4j
@RestController
@RequestMapping("/api/auth/first-time-setup")
@RequiredArgsConstructor
@Tag(
        name = "First-Time Setup (Production)",
        description = """
        Production-grade 3-step first-time setup with password staging.
        
        **Key Features:**
        - Password validated and STAGED in Redis (Step 1)
        - OTP verified separately (Step 2)
        - Password COMMITTED to DB only after OTP (Step 3)
        - Rollback possible before Step 3
        - Maximum security with dual-factor confirmation
        
        **Flow:**
        1. Change password → Password staged + OTP sent
        2. Verify OTP → Get verification token
        3. Complete → Password committed to DB
        """
)
public class FirstTimeSetupController {

    private final FirstTimeLoginSetupService setupService;
    private final Clock clock;

    /* =========================
       STEP 1: Change Password (STAGE + Send OTP)
       ========================= */

    @PostMapping(value = "/change-password",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Step 1/3: Change password and send OTP",
            description = """
            **STAGE password in Redis and send OTP.**
            
            ⭐ **IMPORTANT:** Password is NOT saved to database yet!
            It's validated and STAGED in Redis for 15 minutes.
            
            **What Happens:**
            1. Validates temporary token
            2. Validates password (complexity, strength, history)
            3. Hashes password
            4. **STAGES** hashed password in Redis (15-min expiry)
            5. Locks temporary password
            6. Sends OTP via SMS + Email
            7. Returns success
            
            **After Success:**
            - Password is STAGED (not in DB)
            - Temp password is LOCKED
            - OTP sent to phone (10-min validity)
            - Proceed to Step 2 to verify OTP
            
            **Security:**
            - Password validated early (good UX)
            - Password staged in Redis (encrypted)
            - NOT in database until OTP verified
            - Can rollback if needed
            
            **Rate Limiting:**
            - 5 requests per 15 minutes
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Password staged successfully, OTP sent",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                        {
                          "success": true,
                          "message": "Password staged successfully. OTP sent to your phone.",
                          "data": null
                        }
                        """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid password or user state",
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
                    responseCode = "429",
                    description = "Rate limit exceeded"
            )
    })
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "New password",
            content = @Content(
                    schema = @Schema(implementation = ChangePasswordRequest.class),
                    examples = @ExampleObject(
                            value = """
                    {
                      "newPassword": "MyNewSecure123!@"
                    }
                    """
                    )
            )
    )
    public Mono<ResponseEntity<ApiResponse<Void>>> changePassword(
            @RequestHeader("Authorization") String tempToken,
            @Valid @RequestBody ChangePasswordRequest request) {

        Instant startTime = clock.instant();
        log.info("🔑 [STEP 1/3] Password change + staging at {}", startTime);

        return setupService.changePasswordFirstTime(tempToken, request)
                .<ResponseEntity<ApiResponse<Void>>>map(result -> {
                    if (result.isRateLimited()) {
                        log.warn("⚠️ Rate limited at {}", clock.instant());
                        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                .body(ApiResponse.<Void>error(
                                        result.getMessage(),
                                        "RATE_LIMIT_EXCEEDED"
                                ));
                    }

                    if (!result.isSent()) {
                        log.warn("⚠️ OTP send failed at {}", clock.instant());
                        return ResponseEntity.status(HttpStatus.MULTI_STATUS)
                                .body(ApiResponse.<Void>error(
                                        result.getMessage(),
                                        "OTP_SEND_FAILED"
                                ));
                    }

                    log.info("✅ [STEP 1/3] Password STAGED + OTP sent at {}", clock.instant());

                    return ResponseEntity.ok(ApiResponse.<Void>success(
                            "Password staged successfully. OTP sent to your phone.",
                            clock.instant()
                    ));
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    log.warn("❌ Invalid state: {}", e.getMessage());
                    return Mono.just(ResponseEntity.<ApiResponse<Void>>badRequest()
                            .body(ApiResponse.<Void>error(
                                    e.getMessage(),
                                    "INVALID_STATE"
                            )));
                })
                .onErrorResume(Exception.class, e -> {
                    log.error("❌ [STEP 1/3] Failed: {}", e.getMessage());
                    return Mono.just(ResponseEntity.<ApiResponse<Void>>status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(ApiResponse.<Void>error(
                                    "Failed to process request. Please try again.",
                                    "SERVER_ERROR"
                            )));
                });
    }

    /* =========================
       STEP 2: Verify OTP
       ========================= */

    @Operation(
            summary = "Verify OTP (Step 2)",
            description = """
                Step 2: Verify OTP and receive verification token.
                
                Flow:
                1. Validate OTP from Step 1
                2. Generate verification token (5-min expiry)
                3. Return token for Step 3
                
                Max 3 attempts per OTP.
                After verification, proceed to Step 3 with verification token.
                """,
            security = {}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "OTP verification result",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "OTP Valid",
                                            value = """
                                                {
                                                  "success": true,
                                                  "message": "OTP verified! Proceeding to activate account...",
                                                  "data": {
                                                    "valid": true,
                                                    "verificationToken": "vfy_abc123...",
                                                    "expiresInSeconds": 300,
                                                    "message": "OTP verified! Proceeding to activate account..."
                                                  },
                                                  "timestamp": "2024-03-15T14:22:30Z"
                                                }
                                                """
                                    ),
                                    @ExampleObject(
                                            name = "OTP Invalid",
                                            value = """
                                                {
                                                  "success": false,
                                                  "message": "Invalid OTP",
                                                  "data": {
                                                    "valid": false,
                                                    "expired": false,
                                                    "attemptsExceeded": false,
                                                    "remainingAttempts": 2,
                                                    "message": "Invalid OTP. 2 attempts remaining."
                                                  },
                                                  "timestamp": "2024-03-15T14:22:30Z"
                                                }
                                                """
                                    )
                            }
                    )
            )
    })
    @PostMapping("/verify-otp")
    public Mono<ResponseEntity<ApiResponse<OtpVerificationResult>>> verifyOtp(
            @Parameter(
                    description = "Temporary token from login",
                    required = true
            )
            @RequestHeader("Authorization") String tempToken,

            @Parameter(
                    description = "OTP verification request",
                    required = true,
                    schema = @Schema(implementation = VerifyOtpRequest.class)
            )
            @Valid @RequestBody VerifyOtpRequest request) {

        Instant startTime = clock.instant();
        log.info("🔍 [STEP 2/3] OTP verification at {}", startTime);

        return setupService.verifyOtpAndCompleteSetup(tempToken, request)
                .map(result -> {
                    Duration duration = Duration.between(startTime, clock.instant());

                    if (!result.isValid()) {
                        log.warn("❌ [STEP 2/3] OTP invalid at {} after {}", clock.instant(), duration);

                        return ResponseEntity
                                .badRequest()
                                .body(ApiResponse.<OtpVerificationResult>error(
                                        result.getMessage(),
                                        result,
                                        clock.instant()
                                ));
                    }

                    log.info("✅ [STEP 2/3] OTP verified at {} in {}", clock.instant(), duration);

                    return ResponseEntity.ok(
                            ApiResponse.<OtpVerificationResult>success(
                                    result.getMessage(),
                                    result,
                                    clock.instant()
                            )
                    );
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    log.warn("❌ Invalid state: {}", e.getMessage());
                    OtpVerificationResult errorResult = OtpVerificationResult.builder()
                            .valid(false)
                            .message(e.getMessage())
                            .build();
                    return Mono.just(ResponseEntity
                            .badRequest()
                            .body(ApiResponse.<OtpVerificationResult>error(
                                    e.getMessage(),
                                    errorResult,
                                    clock.instant()
                            )));
                })
                .onErrorResume(AuthException.class, e -> {
                    log.error("❌ Auth error: {}", e.getMessage());
                    OtpVerificationResult errorResult = OtpVerificationResult.builder()
                            .valid(false)
                            .message(e.getMessage())
                            .build();
                    return Mono.just(ResponseEntity
                            .status(e.getHttpStatus())
                            .body(ApiResponse.<OtpVerificationResult>error(
                                    e.getMessage(),
                                    errorResult,
                                    clock.instant()
                            )));
                })
                .onErrorResume(Exception.class, e -> {
                    log.error("❌ [STEP 2/3] Failed: {}", e.getMessage());
                    OtpVerificationResult errorResult = OtpVerificationResult.builder()
                            .valid(false)
                            .message("Internal server error")
                            .build();
                    return Mono.just(ResponseEntity
                            .status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(ApiResponse.<OtpVerificationResult>error(
                                    "Failed to verify OTP. Please try again.",
                                    errorResult,
                                    clock.instant()
                            )));
                });
    }

    /* =========================
       STEP 3: Complete Setup (COMMIT to DB)
       ========================= */

    @PostMapping(value = "/complete",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Step 3/3: Complete setup",
            description = """
            **COMMIT password to database and activate account.**
            
            ⭐ **THIS IS WHERE PASSWORD IS SAVED TO DATABASE!**
            
            **What Happens:**
            1. Validates verification token (consumes it - single-use)
            2. Retrieves staged password from Redis
            3. **COMMITS** password to database (FIRST TIME!)
            4. Activates account (forcePasswordChange=false, phoneVerified=true)
            5. Invalidates all sessions
            6. Cleans up Redis keys
            7. Sends confirmation email
            8. Returns full access tokens
            
            **After Success:**
            - Password is NOW in database ✅
            - Account is activated ✅
            - Temp password is dead ✅
            - Full access granted ✅
            
            **Security:**
            - Verification token is single-use
            - All sessions invalidated
            - Staged password cleaned from Redis
            """,
            security = {}
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Setup complete, account activated",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                    {
                      "success": true,
                      "message": "Setup complete! Your account is now activated.",
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
                    responseCode = "401",
                    description = "Invalid or expired verification token"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "No staged password found (restart from Step 1)"
            )
    })
    public Mono<ResponseEntity<ApiResponse<Map<String, String>>>> completeSetup(
            @Valid @RequestBody CompleteSetupRequest request) {

        Instant startTime = clock.instant();
        log.info("🎯 [STEP 3/3] Completing setup - COMMITTING to DB at {}", startTime);

        return setupService.completeSetup(request.verificationToken())
                .map(tokenPair -> {
                    log.info("✅ [STEP 3/3] Setup COMPLETED at {} - Password in DB!",
                            clock.instant());

                    Map<String, String> tokens = Map.of(
                            "accessToken", tokenPair.getAccessToken(),
                            "refreshToken", tokenPair.getRefreshToken()
                    );

                    return ResponseEntity.ok(
                            ApiResponse.<Map<String, String>>success(
                                    "Setup complete! Your account is now activated.",
                                    tokens,
                                    clock.instant()
                            )
                    );
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    log.warn("❌ Invalid state: {}", e.getMessage());

                    Map<String, String> errorData = Map.of(
                            "error", "INVALID_STATE",
                            "message", e.getMessage()
                    );

                    return Mono.just(ResponseEntity.badRequest()
                            .body(ApiResponse.<Map<String, String>>error(
                                    e.getMessage(),
                                    errorData,
                                    clock.instant()
                            )));
                })
                .onErrorResume(AuthException.class, e -> {
                    log.error("❌ Auth error: {}", e.getMessage());

                    Map<String, String> errorData = Map.of(
                            "error", "INVALID_TOKEN",
                            "message", "The verification token is invalid or expired"
                    );

                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(ApiResponse.<Map<String, String>>error(
                                    "Invalid or expired verification token",
                                    errorData,
                                    clock.instant()
                            )));
                })
                .onErrorResume(Exception.class, e -> {
                    log.error("❌ [STEP 3/3] Failed: {}", e.getMessage());

                    Map<String, String> errorData = Map.of(
                            "error", "SERVER_ERROR",
                            "message", "An unexpected error occurred"
                    );

                    return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(ApiResponse.<Map<String, String>>error(
                                    "Failed to complete setup. Please try again.",
                                    errorData,
                                    clock.instant()
                            )));
                });
    }

    /* =========================
       Resend OTP
       ========================= */

    @PostMapping(value = "/resend-otp", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "Resend OTP",
            description = """
            Resend OTP if not received or expired.
            
            **Use Cases:**
            - SMS not received
            - OTP expired (10 minutes)
            - Used all 3 attempts
            
            **What Happens:**
            - Invalidates previous OTP
            - Generates new 6-digit OTP
            - Sends via SMS
            - Resets attempt counter
            
            **Rate Limiting:**
            - Shared with Step 1
            - Max 5 requests per 15 minutes
            """,
            security = @SecurityRequirement(name = "Bearer Authentication")
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "OTP resent successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Rate limit exceeded"
            )
    })
    public Mono<ResponseEntity<ApiResponse<Void>>> resendOtp(
            @RequestHeader("Authorization") String tempToken) {

        Instant startTime = clock.instant();
        log.info("🔄 OTP resend at {}", startTime);

        return setupService.resendOtp(tempToken)
                .<ResponseEntity<ApiResponse<Void>>>map(result -> {
                    if (result.isRateLimited()) {
                        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                .body(ApiResponse.<Void>error(
                                        result.getMessage(),
                                        "RATE_LIMIT_EXCEEDED"
                                ));
                    }

                    if (!result.isSent()) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.<Void>error(
                                        result.getMessage(),
                                        "OTP_SEND_FAILED"
                                ));
                    }

                    log.info("✅ OTP resent at {}", clock.instant());

                    return ResponseEntity.ok(ApiResponse.<Void>success(
                            result.getMessage(),
                            clock.instant()
                    ));
                })
                .onErrorResume(IllegalStateException.class, e -> {
                    log.warn("❌ Invalid state: {}", e.getMessage());
                    return Mono.just(ResponseEntity.<ApiResponse<Void>>badRequest()
                            .body(ApiResponse.<Void>error(
                                    e.getMessage(),
                                    "INVALID_STATE"
                            )));
                })
                .onErrorResume(Exception.class, e -> {
                    log.error("❌ OTP resend failed: {}", e.getMessage());
                    return Mono.just(ResponseEntity.<ApiResponse<Void>>status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(ApiResponse.<Void>error(
                                    "Failed to resend OTP. Please try again.",
                                    "SERVER_ERROR"
                            )));
                });
    }
}