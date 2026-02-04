package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.config.core.AppConfigProperties;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.regex.Pattern;

/**
 * Bootstrap Validation Service
 *
 * Validates bootstrap configuration before attempting Super Admin creation.
 * Uses Clock for timestamp tracking in validation logs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapValidationService {

    /* =========================
       Dependencies
       ========================= */

    private final Clock clock;

    /* =========================
       Validation Patterns
       ========================= */

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final Pattern E164_PHONE_PATTERN = Pattern.compile(
            "^\\+?[1-9]\\d{1,14}$"
    );

    /* =========================
       Configuration Validation
       ========================= */

    /**
     * Validate bootstrap configuration from app properties
     */
    public boolean validateBootstrapConfig(AppConfigProperties config) {
        Instant now = clock.instant();

        log.debug("🔍 Validating bootstrap configuration at {}", now);

        // Check if configuration exists
        if (config == null) {
            log.error("❌ Bootstrap configuration is null at {}", now);
            return false;
        }

        // Validate email
        String email = config.getSuperAdminEmail();
        if (!validateEmail(email)) {
            log.error("❌ Invalid or missing Super Admin email at {}: {}",
                    now, HelperUtils.maskEmail(email));
            return false;
        }

        // Validate phone
        String phone = config.getSuperAdminPhone();
        if (!validatePhone(phone)) {
            log.error("❌ Invalid or missing Super Admin phone at {}: {}",
                    now, maskPhone(phone));
            return false;
        }

        log.info("✅ Bootstrap configuration validated successfully at {}", now);
        log.debug("  Email: {}", HelperUtils.maskEmail(email));
        log.debug("  Phone: {}", maskPhone(phone));

        return true;
    }

    /* =========================
       Field Validation
       ========================= */

    /**
     * Validate email format
     */
    private boolean validateEmail(String email) {
        if (StringUtils.isBlank(email)) {
            return false;
        }

        email = email.trim().toLowerCase();
        return EMAIL_PATTERN.matcher(email).matches();
    }

    /**
     * Validate phone format
     * Accepts various formats and normalizes to E.164
     */
    private boolean validatePhone(String phone) {
        if (StringUtils.isBlank(phone)) {
            return false;
        }

        // Remove all whitespace
        phone = phone.replaceAll("\\s+", "");

        // Try to normalize to E.164
        String normalized = normalizePhone(phone);

        return E164_PHONE_PATTERN.matcher(normalized).matches();
    }

    /* =========================
       Phone Normalization
       ========================= */

    /**
     * Normalize phone number to E.164 format
     * Handles Kenyan numbers specifically
     */
    private String normalizePhone(String phone) {
        if (StringUtils.isBlank(phone)) {
            return "";
        }

        phone = phone.trim().replaceAll("\\s+", "");

        // Already in E.164 format
        if (phone.startsWith("+")) {
            return phone;
        }

        // Kenyan number starting with 0
        if (phone.startsWith("0") && phone.length() == 10) {
            return "+254" + phone.substring(1);
        }

        // Kenyan number without country code
        if (phone.startsWith("254") && phone.length() == 12) {
            return "+" + phone;
        }

        // Kenyan number without prefix
        if (phone.startsWith("7") && phone.length() == 9) {
            return "+254" + phone;
        }

        // Default: add + if missing
        if (!phone.startsWith("+")) {
            return "+" + phone;
        }

        return phone;
    }

    /* =========================
       Masking (GDPR Compliance)
       ========================= */

    /**
     * Mask phone for logging (GDPR compliance)
     */
    private String maskPhone(String phone) {
        if (phone == null) {
            return "null";
        }
        if (phone.length() < 4) {
            return "***";
        }
        return phone.substring(0, 4) + "***" +
                phone.substring(Math.max(phone.length() - 3, 4));
    }
}