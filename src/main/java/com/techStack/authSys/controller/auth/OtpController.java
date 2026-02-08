package com.techStack.authSys.controller.auth;

import com.techStack.authSys.service.verification.OtpService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * OTP Controller
 *
 * Handles OTP generation, sending, and verification.
 * Uses Clock for timestamp tracking and reactive patterns.
 */
@Slf4j
@RestController
@RequestMapping("/api/otp")
@RequiredArgsConstructor
public class OtpController {

    /* =========================
       Dependencies
       ========================= */

    private final OtpService otpService;
    private final Clock clock;

    /* =========================
       OTP Operations
       ========================= */

    /**
     * Send OTP to phone number (async)
     */
    @PostMapping("/send")
    public Mono<ResponseEntity<Map<String, Object>>> sendOtp(
            @RequestParam String phoneNumber) {

        Instant sendTime = clock.instant();

        log.info("OTP send request at {} for phone: {}",
                sendTime, HelperUtils.maskPhone(phoneNumber));

        return Mono.fromCallable(() -> otpService.generateOTP(phoneNumber))
                .flatMap(otp -> {
                    // Save OTP
                    otpService.saveOtp(phoneNumber, otp);

                    // Send OTP asynchronously
                    return otpService.sendOtpAsync(phoneNumber, otp)
                            .then(Mono.fromCallable(() -> {
                                Instant completionTime = clock.instant();
                                log.info("✅ OTP sent successfully at {} to: {}",
                                        completionTime, HelperUtils.maskPhone(phoneNumber));

                                // Use HashMap to ensure Object type
                                Map<String, Object> response = new HashMap<>();
                                response.put("success", true);
                                response.put("message", "OTP sent successfully to " +
                                        HelperUtils.maskPhone(phoneNumber));
                                response.put("timestamp", completionTime.toString());

                                return ResponseEntity.ok(response);
                            }));
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ Failed to send OTP at {} to {}: {}",
                            errorTime, HelperUtils.maskPhone(phoneNumber), e.getMessage());

                    // Use HashMap to ensure Object type
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("success", false);
                    errorResponse.put("message", "Failed to send OTP: " + e.getMessage());
                    errorResponse.put("timestamp", errorTime.toString());

                    return Mono.just(ResponseEntity
                            .status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(errorResponse));
                });
    }

    /**
     * Verify OTP
     */
    @PostMapping("/verify")
    public Mono<ResponseEntity<Map<String, Object>>> verifyOtp(
            @RequestParam String phoneNumber,
            @RequestParam String otp) {

        Instant verifyTime = clock.instant();

        log.info("OTP verification request at {} for phone: {}",
                verifyTime, HelperUtils.maskPhone(phoneNumber));

        return Mono.fromCallable(() -> otpService.verifyOtp(phoneNumber, otp))
                .map(verified -> {
                    Instant completionTime = clock.instant();

                    if (verified) {
                        log.info("✅ OTP verified successfully at {} for: {}",
                                completionTime, HelperUtils.maskPhone(phoneNumber));

                        // Use HashMap to ensure Object type
                        Map<String, Object> response = new HashMap<>();
                        response.put("success", true);
                        response.put("message", "OTP verified successfully");
                        response.put("timestamp", completionTime.toString());

                        return ResponseEntity.ok(response);
                    } else {
                        log.warn("❌ OTP verification failed at {} for: {}",
                                completionTime, HelperUtils.maskPhone(phoneNumber));

                        // Use HashMap to ensure Object type
                        Map<String, Object> errorResponse = new HashMap<>();
                        errorResponse.put("success", false);
                        errorResponse.put("message", "Invalid or expired OTP");
                        errorResponse.put("timestamp", completionTime.toString());

                        return ResponseEntity
                                .status(HttpStatus.UNAUTHORIZED)
                                .body(errorResponse);
                    }
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();
                    log.error("❌ OTP verification error at {} for {}: {}",
                            errorTime, HelperUtils.maskPhone(phoneNumber), e.getMessage());

                    // Use HashMap to ensure Object type
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("success", false);
                    errorResponse.put("message", "Failed to verify OTP: " + e.getMessage());
                    errorResponse.put("timestamp", errorTime.toString());

                    return Mono.just(ResponseEntity
                            .status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(errorResponse));
                });
    }

    /**
     * Resend OTP
     */
    @PostMapping("/resend")
    public Mono<ResponseEntity<Map<String, Object>>> resendOtp(
            @RequestParam String phoneNumber) {

        Instant resendTime = clock.instant();

        log.info("OTP resend request at {} for phone: {}",
                resendTime, HelperUtils.maskPhone(phoneNumber));

        // Call the same send OTP logic
        return sendOtp(phoneNumber);
    }
}