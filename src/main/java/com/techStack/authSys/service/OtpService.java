package com.techStack.authSys.service;

import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.google.cloud.firestore.Firestore;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@Service
public class OtpService {

    private static final Logger logger = LoggerFactory.getLogger(OtpService.class);

    @Value("${brevo.api.key}")
    private String apiKey;

    @Value("${brevo.sms.sender}")
    private String smsSender;

    private final Firestore firestore;
    private final SecureRandom secureRandom = new SecureRandom();
    private final OkHttpClient httpClient = new OkHttpClient();

    public OtpService(
            @Value("${brevo.api.key}") String apiKey,
            @Value("${brevo.sms.sender}") String smsSender,
            Firestore firestore
    ) {
        this.apiKey = apiKey;
        this.smsSender = smsSender;
        this.firestore = firestore;
    }

    @PostConstruct
    public void logConfiguration() {
        logger.info("Brevo API Key: {}", apiKey != null && !apiKey.isEmpty() ? "Loaded" : "NOT SET");
        logger.info("SMS Sender: {}", smsSender);

        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalStateException("Brevo API key is missing!");
        }
    }

    public String generateOTP(String userId) {
        int otp = 100000 + secureRandom.nextInt(900000); // Generate 6-digit OTP
        logger.info("Generated OTP for user {}: {}", userId, otp);
        return String.valueOf(otp);
    }

    public String hashOtp(String otp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(otp.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            logger.error("Error hashing OTP", e);
            throw new RuntimeException("Error hashing OTP", e);
        }
    }

    public void saveOtp(String userId, String otp) {
        String hashedOtp = hashOtp(otp);
        Map<String, Object> otpData = new HashMap<>();
        otpData.put("otp", hashedOtp);
        otpData.put("expiresAt", System.currentTimeMillis() + (10 * 60 * 1000)); // 10-minute expiry
        otpData.put("attempts", 0);

        try {
            firestore.collection("email_verifications").document(userId).set(otpData).get();
            logger.info("OTP saved for user {}", userId);
        } catch (InterruptedException | ExecutionException e) {
            logger.error("Error saving OTP for user {}", userId, e);
            throw new RuntimeException("Error saving OTP", e);
        }
    }

    public boolean verifyOtp(String userId, String otp) {
        try {
            Map<String, Object> data = firestore.collection("email_verifications").document(userId).get().get().getData();
            if (data == null) {
                logger.warn("No OTP found for user {}", userId);
                return false;
            }

            String storedHashedOtp = (String) data.get("otp");
            long expiresAt = (long) data.get("expiresAt");
            int attempts = ((Long) data.get("attempts")).intValue();

            if (System.currentTimeMillis() > expiresAt || attempts >= 3) {
                logger.warn("OTP expired or max attempts reached for user {}", userId);
                return false;
            }

            if (hashOtp(otp).equals(storedHashedOtp)) {
                firestore.collection("email_verifications").document(userId).delete(); // Remove OTP after use
                logger.info("OTP verified successfully for user {}", userId);
                return true;
            } else {
                firestore.collection("email_verifications").document(userId).update("attempts", attempts + 1);
                logger.warn("Invalid OTP attempt for user {}", userId);
                return false;
            }
        } catch (InterruptedException | ExecutionException e) {
            logger.error("Error verifying OTP for user {}", userId, e);
            throw new RuntimeException("Error verifying OTP", e);
        }
    }

    public Mono<Void> sendOtpAsync(String phoneNumber, String otp) {
        return Mono.defer(() -> {
            try {
                sendOtp(phoneNumber, otp);
                return Mono.empty();
            } catch (Exception e) {
                logger.error("Failed to send OTP asynchronously to {}", phoneNumber, e);
                return Mono.error(e);
            }
        });
    }

    public void sendOtp(String phoneNumber, String otp) {

        String jsonBody = String.format(
                "{\"sender\":\"%s\",\"recipient\":\"%s\",\"content\":\"Your OTP is: %s. It expires in 10 minutes.\"}",
                smsSender, phoneNumber, otp
        );

        RequestBody requestBody = RequestBody.create(jsonBody, MediaType.get("application/json"));

        Request request = new Request.Builder()
                .url("https://api.brevo.com/v3/transactionalSMS/sms")
                .post(requestBody)
                .addHeader("x-api-key", apiKey)  // Fixed API key header
                .addHeader("Content-Type", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String responseBody = response.body() != null ? response.body().string() : "No response body";
                logger.error("Failed to send OTP to {}. Status: {}. Response: {}", phoneNumber, response.code(), responseBody);
                throw new IOException("Failed to send OTP. Status: " + response.code() + ", Response: " + responseBody);
            }
            logger.info("OTP sent successfully to {}", phoneNumber);
        } catch (IOException e) {
            logger.error("Failed to send OTP to {}", phoneNumber, e);
            throw new RuntimeException("Failed to send OTP via SMS: " + e.getMessage(), e);
        }
    }

    public <V> Mono<Object> triggerOtp(V user) {
        return Mono.empty(); // or Mono.just("OTP Triggered") if testing
    }

}
