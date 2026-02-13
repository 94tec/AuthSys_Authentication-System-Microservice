package com.techStack.authSys.controller.auth;

import com.techStack.authSys.dto.response.ApiResponse;
import com.techStack.authSys.dto.response.OtpResult;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.service.security.OtpService;
import com.techStack.authSys.util.validation.HelperUtils;
import io.swagger.v3.oas.annotations.Operation;
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
@Tag(name = "OTP", description = "OTP generation and verification (testing/admin)")
public class OtpController {

    private final OtpService otpService;
    private final Clock clock;

    /**
     * Send Setup OTP (for testing)
     */
    @Operation(
            summary = "Send Setup OTP",
            description = "Generate and send setup OTP for testing purposes"
    )
    @PostMapping("/send/setup")
    public Mono<ResponseEntity<ApiResponse<String>>> sendSetupOtp(
            @RequestParam String userId,
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

    /**
     * Send Login OTP (for testing)
     */
    @Operation(
            summary = "Send Login OTP",
            description = "Generate and send login OTP for testing purposes"
    )
    @PostMapping("/send/login")
    public Mono<ResponseEntity<ApiResponse<String>>> sendLoginOtp(
            @RequestParam String userId,
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

    /**
     * Verify Setup OTP (for testing)
     */
    @Operation(
            summary = "Verify Setup OTP",
            description = "Verify setup OTP for testing purposes"
    )
    @PostMapping("/verify/setup")
    public Mono<ResponseEntity<ApiResponse<OtpVerificationResult>>> verifySetupOtp(
            @RequestParam String userId,
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

    /**
     * Verify Login OTP (for testing)
     */
    @Operation(
            summary = "Verify Login OTP",
            description = "Verify login OTP for testing purposes"
    )
    @PostMapping("/verify/login")
    public Mono<ResponseEntity<ApiResponse<OtpVerificationResult>>> verifyLoginOtp(
            @RequestParam String userId,
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