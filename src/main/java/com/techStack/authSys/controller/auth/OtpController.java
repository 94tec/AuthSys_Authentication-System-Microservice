package com.techStack.authSys.controller.auth;

import com.techStack.authSys.service.verification.OtpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

/**
 * OTP Controller
 *
 * Handles OTP generation and sending.
 * Uses Clock for timestamp tracking.
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
     * Send OTP to phone number
     */
    @PostMapping("/send")
    public ResponseEntity<Map<String, Object>> sendOtp(@RequestParam String phoneNumber) {
        Instant sendTime = clock.instant();

        log.info("OTP send request at {} for phone: {}", sendTime, maskPhone(phoneNumber));

        String otp = otpService.generateOTP(phoneNumber);
        otpService.saveOtp(phoneNumber, otp);
        otpService.sendOtp(phoneNumber, otp);

        log.info("✅ OTP sent successfully at {} to: {}", sendTime, maskPhone(phoneNumber));

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "OTP sent successfully to " + maskPhone(phoneNumber),
                "timestamp", sendTime.toString()
        ));
    }

    /* =========================
       Helper Methods
       ========================= */

    /**
     * Mask phone number for logging
     */
    private String maskPhone(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 4) {
            return "***";
        }
        return phoneNumber.substring(0, 3) + "***" +
                phoneNumber.substring(Math.max(phoneNumber.length() - 2, 3));
    }
}