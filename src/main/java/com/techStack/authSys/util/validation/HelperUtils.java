package com.techStack.authSys.util.validation;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.models.user.UserStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Collections;
import java.util.concurrent.TimeoutException;

/**
 * Helper Utilities
 *
 * Provides utility methods for validation, masking, and user creation.
 * All masking methods are GDPR-compliant.
 */
public class HelperUtils {

    private static final String SYSTEM_CREATOR = "BOOTSTRAP_SYSTEM";
    private static final String SYSTEM_IP = "127.0.0.1";
    private static final String DEVICE_FINGERPRINT = "BOOTSTRAP_DEVICE";

    private HelperUtils() {
        // Utility class - private constructor
    }

    /* =========================
       Email Utilities
       ========================= */

    /**
     * Masks email for GDPR-compliant logging
     *
     * Examples:
     * john.doe@gmail.com → j***e@gmail.com
     * a@test.com → a*****@test.com
     */
    public static String maskEmail(String email) {
        if (email == null || email.trim().isEmpty()) return "*****";

        String trimmedEmail = email.trim();
        int atIndex = trimmedEmail.indexOf('@');
        if (atIndex <= 0) return "*****";

        String localPart = trimmedEmail.substring(0, atIndex);
        String domain = trimmedEmail.substring(atIndex + 1);

        if (localPart.length() == 1) {
            return localPart + "*****@" + domain;
        } else if (localPart.length() == 2) {
            return localPart.charAt(0) + "*****" + localPart.charAt(1) + "@" + domain;
        } else {
            // a***c@gmail.com format
            return localPart.charAt(0) + "*****" + localPart.charAt(localPart.length() - 1) + "@" + domain;
        }
    }

    /**
     * Normalizes email to lowercase and trimmed
     */
    public static String normalizeEmail(String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    /* =========================
       Phone Utilities
       ========================= */

    /**
     * Masks phone number for GDPR-compliant logging
     *
     * Examples:
     * +254712345678 → +254***5678
     * 0712345678 → 071***5678
     * 712345678 → 712***678
     */
    public static String maskPhone(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            return "***";
        }

        // Remove whitespace
        String cleaned = phoneNumber.replaceAll("\\s+", "");

        if (cleaned.length() < 4) {
            return "***";
        }

        // For international format (+254...)
        if (cleaned.startsWith("+")) {
            if (cleaned.length() <= 7) {
                return cleaned.substring(0, 4) + "***";
            }
            return cleaned.substring(0, 4) + "***" +
                    cleaned.substring(Math.max(cleaned.length() - 4, 4));
        }

        // For local format (0712... or 712...)
        if (cleaned.length() <= 6) {
            return cleaned.substring(0, 3) + "***";
        }

        return cleaned.substring(0, 3) + "***" +
                cleaned.substring(Math.max(cleaned.length() - 4, 3));
    }

    /**
     * Normalizes phone number to E.164 format
     * Handles Kenyan numbers specifically
     *
     * Examples:
     * 0712345678 → +254712345678
     * 712345678 → +254712345678
     * +254712345678 → +254712345678
     */
    public static String normalizePhone(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            return "";
        }

        // Remove all whitespace and dashes
        String cleaned = phoneNumber.replaceAll("[\\s-]", "");

        // Already in E.164 format
        if (cleaned.startsWith("+")) {
            return cleaned;
        }

        // Kenyan number starting with 0
        if (cleaned.startsWith("0") && cleaned.length() == 10) {
            return "+254" + cleaned.substring(1);
        }

        // Kenyan number without country code
        if (cleaned.startsWith("254") && cleaned.length() == 12) {
            return "+" + cleaned;
        }

        // Kenyan number without prefix (7XX or 1XX)
        if ((cleaned.startsWith("7") || cleaned.startsWith("1")) && cleaned.length() == 9) {
            return "+254" + cleaned;
        }

        // Default: add + if missing
        if (!cleaned.startsWith("+")) {
            return "+" + cleaned;
        }

        return cleaned;
    }

    /**
     * Validates phone number format
     */
    public static boolean isValidPhone(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.isBlank()) {
            return false;
        }

        String normalized = normalizePhone(phoneNumber);

        // E.164 format: + followed by 1-15 digits
        return normalized.matches("^\\+[1-9]\\d{1,14}$");
    }

    /* =========================
       IP Address Utilities
       ========================= */

    /**
     * Masks IP address for GDPR-compliant logging
     *
     * Examples:
     * 192.168.1.100 → 192.168.***.***
     * 2001:0db8:85a3:0000:0000:8a2e:0370:7334 → 2001:0db8:85a3:****
     * 10.0.0.1 → 10.0.***.***
     */
    public static String maskIpAddress(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return "***.***.***.**";
        }

        String ip = ipAddress.trim();

        // IPv6 detection
        if (ip.contains(":")) {
            return maskIpv6(ip);
        }

        // IPv4
        return maskIpv4(ip);
    }

    /**
     * Masks IPv4 address
     * 192.168.1.100 → 192.168.***.***
     */
    private static String maskIpv4(String ip) {
        String[] parts = ip.split("\\.");

        if (parts.length != 4) {
            return "***.***.***.**";
        }

        // Keep first two octets, mask last two
        return parts[0] + "." + parts[1] + ".***.**";
    }

    /**
     * Masks IPv6 address
     * 2001:0db8:85a3:0000:0000:8a2e:0370:7334 → 2001:0db8:85a3:****
     */
    private static String maskIpv6(String ip) {
        String[] parts = ip.split(":");

        if (parts.length < 3) {
            return "****:****:****";
        }

        // Keep first three groups, mask the rest
        return parts[0] + ":" + parts[1] + ":" + parts[2] + ":****";
    }

    /* =========================
       Error Handling
       ========================= */

    /**
     * Determines if an error is retryable
     */
    public static boolean isRetryableError(Throwable throwable) {
        // Merge both logics: status checks first, then specifics, fall back to message/IO checks
        if (throwable instanceof CustomException custom &&
                custom.getStatus() != null &&
                custom.getStatus().is5xxServerError()) {
            return true;
        }

        if (throwable instanceof TimeoutException ||
                throwable instanceof java.net.ConnectException ||
                throwable instanceof java.net.SocketTimeoutException ||
                throwable instanceof org.springframework.web.reactive.function.client.WebClientRequestException ||
                throwable instanceof java.net.SocketException ||
                throwable instanceof java.io.IOException) {
            return true;
        }

        if (throwable instanceof FirebaseAuthException fae) {
            String errorCode = fae.getErrorCode() != null ? fae.getErrorCode().name() : "";
            int status = fae.getHttpResponse() != null ? fae.getHttpResponse().getStatusCode() : -1;
            return (status >= 500) ||
                    "INTERNAL_ERROR".equalsIgnoreCase(errorCode) ||
                    "UNAVAILABLE".equalsIgnoreCase(errorCode) ||
                    "UNKNOWN".equalsIgnoreCase(errorCode);
        }

        if (throwable instanceof ResponseStatusException rse &&
                rse.getStatusCode().is5xxServerError()) {
            return true;
        }

        // Fallback message checks
        return throwable.getMessage() != null && (
                throwable.getMessage().contains("timeout") ||
                        throwable.getMessage().contains("temporarily unavailable") ||
                        throwable.getMessage().contains("connection reset") ||
                        throwable.getMessage().contains("UNAVAILABLE"));
    }

    /* =========================
       User Builders
       ========================= */

    /**
     * Builds a super admin user for bootstrap
     */
    public static User buildSuperAdminUser(String email, String phone, String password) {
        Instant now = Instant.now();
        User admin = new User();
        admin.setCreatedAt(now);
        admin.setUpdatedAt(now);
        admin.setCreatedBy(SYSTEM_CREATOR);
        admin.setEmail(email);
        admin.setEmailVerified(true);
        admin.setPhoneNumber(phone);
        admin.setPassword(password);
        admin.setStatus(UserStatus.ACTIVE);
        admin.setEnabled(true);
        admin.setForcePasswordChange(true);
        admin.setAccountLocked(false);
        admin.setFirstName("Super");
        admin.setLastName("Admin");
        admin.setUsername("superadmin");
        admin.setKnownDeviceFingerprints("DEVICE_FINGERPRINT");
        return admin;
    }
}