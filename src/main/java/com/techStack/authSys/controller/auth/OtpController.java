package com.techStack.authSys.controller.auth;


import com.techStack.authSys.service.verification.OtpService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/otp")
public class OtpController {

    private final OtpService otpService;

    public OtpController(OtpService otpService) {
        this.otpService = otpService;
    }

    @PostMapping("/send")
    public ResponseEntity<String> sendOtp(@RequestParam String phoneNumber) {
        String otp = otpService.generateOTP(phoneNumber);
        otpService.saveOtp(phoneNumber, otp);
        otpService.sendOtp(phoneNumber, otp);
        return ResponseEntity.ok("OTP sent successfully to " + phoneNumber);
    }
}

