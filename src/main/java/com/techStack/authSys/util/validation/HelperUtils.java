package com.techStack.authSys.util.validation;

import com.google.firebase.auth.FirebaseAuthException;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.user.User;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.concurrent.TimeoutException;

public class HelperUtils {

    private static final String SYSTEM_CREATOR = "BOOTSTRAP_SYSTEM";
    private static final String SYSTEM_IP = "127.0.0.1";
    private static final String DEVICE_FINGERPRINT = "BOOTSTRAP_DEVICE";

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
    public static String normalizeEmail(String email) {
        return email != null ? email.trim().toLowerCase() : null;
    }

    public static String normalizePhone(String phone) {
        if (phone == null || phone.isBlank()) return null;
        phone = phone.trim().replaceAll("\\s+", "");
        if (phone.startsWith("0")) return "+254" + phone.substring(1);
        if (phone.startsWith("254")) return "+" + phone;
        if (!phone.startsWith("+")) return "+" + phone;
        return phone;
    }
    public static boolean isRetryableError(Throwable throwable) {
        // Merge both logics: status checks first, then specifics, fall back to message/IO checks
        if (throwable instanceof CustomException custom && custom.getStatus() != null && custom.getStatus().is5xxServerError()) {
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
        if (throwable instanceof ResponseStatusException rse && rse.getStatusCode().is5xxServerError()) {
            return true;
        }
        // Fallback message checks
        return throwable.getMessage() != null && (
                throwable.getMessage().contains("timeout") ||
                        throwable.getMessage().contains("temporarily unavailable") ||
                        throwable.getMessage().contains("connection reset") ||
                        throwable.getMessage().contains("UNAVAILABLE"));
    }
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
        admin.setStatus(User.Status.ACTIVE);
        admin.setEnabled(true);
        admin.setForcePasswordChange(true);
        admin.setAccountLocked(false);
        admin.setFirstName("Super");
        admin.setLastName("Admin");
        admin.setUsername("superadmin");
        admin.setDeviceFingerprint(DEVICE_FINGERPRINT);
        return admin;
    }


}
