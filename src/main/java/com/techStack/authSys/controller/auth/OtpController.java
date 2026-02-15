package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.service.security.OtpService;
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
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;

/**
 * OTP Controller
 *
 * Handles OTP operations for testing and admin purposes.
 * For production flows, use FirstTimeSetupController and LoginOtpController.
 */
@Slf4j
@RestController
@RequestMapping("/api/otp")
@RequiredArgsConstructor
@Tag(
        name = "OTP (Testing)",
        description = """
                OTP generation and verification for testing and development.
                
                **⚠️ Development/Testing Only**
                These endpoints are for testing OTP functionality.
                Production flows should use:
                - `/api/auth/first-time-setup/*` for setup OTP
                - `/api/auth/login-otp/*` for login OTP
                
                **Two OTP Types:**
                
                **1. Setup OTP (First-Time Password Change)**
                - Validity: 10 minutes
                - Rate limit: 5 requests per 15 minutes
                - Max attempts: 3
                - Used during first-time user setup
                
                **2. Login OTP (2FA)**
                - Validity: 5 minutes
                - Rate limit: 10 requests per 15 minutes
                - Max attempts: 3
                - Used for login verification
                
                **SMS Providers:**
                - **Development**: Console logging (free)
                - **Sandbox**: Africa's Talking sandbox (free testing)
                - **Production**: Africa's Talking or Twilio (paid)
                
                **Security Features:**
                - Cryptographically random 6-digit OTPs
                - Redis-based storage with auto-expiry
                - Rate limiting to prevent abuse
                - Attempt tracking (max 3 attempts)
                - Phone number masking in logs
                - Independent systems (setup vs login)
                
                **Testing Flow:**
                1. POST /send/setup or /send/login
                2. Check console logs for OTP (dev mode)
                3. POST /verify/setup or /verify/login with OTP
                4. Verify success/failure response
                
                **Rate Limiting:**
                Exceeding rate limits returns 429 with retry-after information.
                """
)
public class OtpController {

    private final OtpService otpService;
    private final Clock clock;

    /* =========================
       Setup OTP (First-Time)
       ========================= */

    @Operation(
            summary = "Send Setup OTP",
            description = """
                    Generate and send setup OTP for testing first-time user flow.
                    
                    **Purpose:**
                    Test OTP functionality for first-time password change flow.
                    
                    **OTP Properties:**
                    - **Validity**: 10 minutes
                    - **Format**: 6-digit numeric code
                    - **Delivery**: SMS to phone number
                    - **Storage**: Redis with auto-expiry
                    - **Attempts**: Maximum 3 verification attempts
                    
                    **Rate Limiting:**
                    - **Limit**: 5 requests per 15 minutes per user
                    - **Response**: 429 Too Many Requests if exceeded
                    - **Retry**: Wait 15 minutes or until rate limit resets
                    
                    **SMS Delivery:**
                    - **Dev Mode**: Printed to console logs
                    - **Sandbox**: Sent via Africa's Talking sandbox
                    - **Production**: Sent via configured provider
                    
                    **Development Testing:**
```bash
                    # 1. Send OTP
                    curl -X POST "http://localhost:8001/api/otp/send/setup" \\
                      -d "userId=user-123" \\
                      -d "phoneNumber=+254712345678"
                    
                    # 2. Check console logs for OTP
                    # Look for: ╔══════════════════════════════╗
                    #           ║      OTP CODE: 123456       ║
                    
                    # 3. Verify OTP
                    curl -X POST "http://localhost:8001/api/otp/verify/setup" \\
                      -d "userId=user-123" \\
                      -d "otp=123456"
```
                    
                    **Production Flow:**
                    In production, use `/api/auth/first-time-setup/change-password`
                    which automatically generates and sends OTP.
                    
                    **Phone Number Format:**
                    - Must be in E.164 format
                    - Example: +254712345678 (Kenya)
                    - Example: +1234567890 (US)
                    """,
            security = {}  // Public for testing
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "OTP sent successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "Setup OTP sent successfully. Check your phone.",
                                              "data": "OTP sent to +254****5678"
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
                                              "data": null
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "500",
                    description = "Failed to send OTP"
            )
    })
    @PostMapping("/send/setup")
    public Mono<ResponseEntity<ApiResponse<String>>> sendSetupOtp(
            @Parameter(
                    description = "User ID to send OTP to",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "Phone number in E.164 format",
                    required = true,
                    example = "+254712345678"
            )
            @RequestParam String phoneNumber) {

        Instant now = clock.instant();
        log.info("🔐 Setup OTP request at {} for: {}", now, HelperUtils.maskPhone(phoneNumber));

        return otpService.generateAndSendSetupOtp(userId, phoneNumber)
                .map(result -> {
                    if (result.isRateLimited()) {
                        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                .body(new ApiResponse<>(
                                        false,
                                        result.getMessage(),
                                        null
                                ));
                    }

                    if (!result.isSent()) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(new ApiResponse<>(
                                        false,
                                        result.getMessage(),
                                        null
                                ));
                    }

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            result.getMessage(),
                            "OTP sent to " + HelperUtils.maskPhone(phoneNumber)
                    ));
                });
    }

    @Operation(
            summary = "Verify Setup OTP",
            description = """
                    Verify setup OTP for testing first-time user flow.
                    
                    **Purpose:**
                    Test OTP verification for first-time password change flow.
                    
                    **Verification Rules:**
                    - OTP must match exactly (case-sensitive for numeric)
                    - OTP must not be expired (< 10 minutes old)
                    - Maximum 3 verification attempts per OTP
                    - After 3 failed attempts, must request new OTP
                    
                    **Response States:**
                    - **Valid**: OTP correct and not expired
                    - **Invalid**: OTP doesn't match
                    - **Expired**: OTP older than 10 minutes
                    - **Attempts Exceeded**: Used all 3 attempts
                    
                    **Attempt Tracking:**
                    - Each verification attempt is counted
                    - Remaining attempts shown in response
                    - After 3 failures, OTP becomes invalid
                    - Must request new OTP to retry
                    
                    **Testing Scenarios:**
```bash
                    # Valid OTP
                    curl -X POST "/api/otp/verify/setup" \\
                      -d "userId=user-123" -d "otp=123456"
                    # → Success: valid=true
                    
                    # Invalid OTP
                    curl -X POST "/api/otp/verify/setup" \\
                      -d "userId=user-123" -d "otp=999999"
                    # → Error: valid=false, remainingAttempts=2
                    
                    # Expired OTP (after 10 minutes)
                    curl -X POST "/api/otp/verify/setup" \\
                      -d "userId=user-123" -d "otp=123456"
                    # → Error: expired=true
```
                    
                    **Production Flow:**
                    In production, use `/api/auth/first-time-setup/verify-otp`
                    which verifies OTP and completes setup in one step.
                    
                    **Security:**
                    - Failed attempts logged for audit
                    - Rate limiting prevents brute force
                    - OTP automatically deleted after verification
                    - Invalid attempts don't reveal OTP format
                    """,
            security = {}  // Public for testing
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "OTP verified successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = OtpVerificationResult.class),
                            examples = @ExampleObject(
                                    value = """
                                            {
                                              "success": true,
                                              "message": "OTP verified successfully",
                                              "data": {
                                                "valid": true,
                                                "expired": false,
                                                "attemptsExceeded": false,
                                                "remainingAttempts": 0,
                                                "message": "OTP verified successfully"
                                              }
                                            }
                                            """
                            )
                    )
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid OTP",
                    content = @Content(
                            mediaType = "application/json",
                            examples = {
                                    @ExampleObject(
                                            name = "Invalid OTP",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "Invalid OTP. 2 attempts remaining.",
                                                      "data": {
                                                        "valid": false,
                                                        "expired": false,
                                                        "attemptsExceeded": false,
                                                        "remainingAttempts": 2,
                                                        "message": "Invalid OTP"
                                                      }
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Expired OTP",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "OTP has expired. Please request a new one.",
                                                      "data": {
                                                        "valid": false,
                                                        "expired": true,
                                                        "attemptsExceeded": false,
                                                        "remainingAttempts": 0,
                                                        "message": "OTP expired"
                                                      }
                                                    }
                                                    """
                                    ),
                                    @ExampleObject(
                                            name = "Attempts Exceeded",
                                            value = """
                                                    {
                                                      "success": false,
                                                      "message": "Maximum OTP attempts exceeded. Please request a new code.",
                                                      "data": {
                                                        "valid": false,
                                                        "expired": false,
                                                        "attemptsExceeded": true,
                                                        "remainingAttempts": 0,
                                                        "message": "Too many attempts"
                                                      }
                                                    }
                                                    """
                                    )
                            }
                    )
            )
    })
    @PostMapping("/verify/setup")
    public Mono<ResponseEntity<ApiResponse<OtpVerificationResult>>> verifySetupOtp(
            @Parameter(
                    description = "User ID",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "6-digit OTP code",
                    required = true,
                    example = "123456"
            )
            @RequestParam String otp) {

        Instant now = clock.instant();
        log.info("🔍 Setup OTP verification at {} for user: {}", now, userId);

        return otpService.verifySetupOtp(userId, otp)
                .map(result -> {
                    if (result.isValid()) {
                        return ResponseEntity.ok(new ApiResponse<>(
                                true,
                                result.getMessage(),
                                result
                        ));
                    } else {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ApiResponse<>(
                                        false,
                                        result.getMessage(),
                                        result
                                ));
                    }
                });
    }

    /* =========================
       Login OTP (2FA)
       ========================= */

    @Operation(
            summary = "Send Login OTP",
            description = """
                    Generate and send login OTP for testing 2FA flow.
                    
                    **Purpose:**
                    Test OTP functionality for login two-factor authentication.
                    
                    **OTP Properties:**
                    - **Validity**: 5 minutes (shorter than setup OTP)
                    - **Format**: 6-digit numeric code
                    - **Delivery**: SMS to registered phone
                    - **Storage**: Redis with auto-expiry
                    - **Attempts**: Maximum 3 verification attempts
                    
                    **Rate Limiting:**
                    - **Limit**: 10 requests per 15 minutes per user
                    - **Higher**: More lenient than setup OTP
                    - **Reason**: Users may need multiple logins
                    - **Response**: 429 if exceeded
                    
                    **Use Case:**
                    Test login OTP flow for users with phoneVerified=true.
                    
                    **Difference from Setup OTP:**
                    | Feature | Setup OTP | Login OTP |
                    |---------|-----------|-----------|
                    | Validity | 10 min | 5 min |
                    | Rate Limit | 5/15min | 10/15min |
                    | Purpose | First-time setup | Login 2FA |
                    | Trigger | Password change | Every login |
                    
                    **Testing:**
```bash
                    # Send login OTP
                    curl -X POST "/api/otp/send/login" \\
                      -d "userId=user-123" \\
                      -d "phoneNumber=+254712345678"
                    
                    # Check console for OTP
                    # Verify within 5 minutes
```
                    
                    **Production Flow:**
                    In production, login automatically sends OTP if user
                    has phoneVerified=true. Use `/api/auth/login-otp/verify`.
                    """,
            security = {}  // Public for testing
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Login OTP sent successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "429",
                    description = "Rate limit exceeded"
            )
    })
    @PostMapping("/send/login")
    public Mono<ResponseEntity<ApiResponse<String>>> sendLoginOtp(
            @Parameter(
                    description = "User ID",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "Phone number in E.164 format",
                    required = true,
                    example = "+254712345678"
            )
            @RequestParam String phoneNumber) {

        Instant now = clock.instant();
        log.info("🔐 Login OTP request at {} for: {}", now, HelperUtils.maskPhone(phoneNumber));

        return otpService.generateAndSendLoginOtp(userId, phoneNumber)
                .map(result -> {
                    if (result.isRateLimited()) {
                        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                                .body(new ApiResponse<>(
                                        false,
                                        result.getMessage(),
                                        null
                                ));
                    }

                    if (!result.isSent()) {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(new ApiResponse<>(
                                        false,
                                        result.getMessage(),
                                        null
                                ));
                    }

                    return ResponseEntity.ok(new ApiResponse<>(
                            true,
                            result.getMessage(),
                            "OTP sent to " + HelperUtils.maskPhone(phoneNumber)
                    ));
                });
    }

    @Operation(
            summary = "Verify Login OTP",
            description = """
                    Verify login OTP for testing 2FA flow.
                    
                    **Purpose:**
                    Test OTP verification for login two-factor authentication.
                    
                    **Verification Rules:**
                    - OTP must match exactly
                    - Must not be expired (< 5 minutes)
                    - Maximum 3 attempts
                    - After 3 failures, request new OTP
                    
                    **Expiry Time:**
                    Login OTP expires in 5 minutes (vs 10 for setup).
                    This is intentional for security.
                    
                    **Testing Complete Flow:**
```bash
                    # 1. Simulate login
                    POST /api/auth/login
                    # → Returns: requiresOtp=true, temporaryToken
                    
                    # 2. Send OTP (automatic in production)
                    POST /api/otp/send/login
                    # → OTP sent to phone
                    
                    # 3. Verify OTP
                    POST /api/otp/verify/login
                    # → Returns: valid=true
                    
                    # 4. Complete login (production)
                    POST /api/auth/login-otp/verify
                    # → Returns: full access tokens
```
                    
                    **Production Flow:**
                    In production, use `/api/auth/login-otp/verify` which
                    verifies OTP and returns full access tokens.
                    
                    **Security:**
                    - Shorter validity (5 min vs 10 min)
                    - Independent from setup OTP
                    - Separate rate limits
                    - Automatic cleanup after verification
                    """,
            security = {}  // Public for testing
    )
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "200",
                    description = "Login OTP verified successfully"
            ),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(
                    responseCode = "400",
                    description = "Invalid, expired, or too many attempts"
            )
    })
    @PostMapping("/verify/login")
    public Mono<ResponseEntity<ApiResponse<OtpVerificationResult>>> verifyLoginOtp(
            @Parameter(
                    description = "User ID",
                    required = true,
                    example = "user-123"
            )
            @RequestParam String userId,

            @Parameter(
                    description = "6-digit OTP code",
                    required = true,
                    example = "123456"
            )
            @RequestParam String otp) {

        Instant now = clock.instant();
        log.info("🔍 Login OTP verification at {} for user: {}", now, userId);

        return otpService.verifyLoginOtp(userId, otp)
                .map(result -> {
                    if (result.isValid()) {
                        return ResponseEntity.ok(new ApiResponse<>(
                                true,
                                result.getMessage(),
                                result
                        ));
                    } else {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ApiResponse<>(
                                        false,
                                        result.getMessage(),
                                        result
                                ));
                    }
                });
    }
}