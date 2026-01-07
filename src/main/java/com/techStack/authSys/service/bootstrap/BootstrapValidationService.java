package com.techStack.authSys.service.bootstrap;

import com.techStack.authSys.config.AppConfigProperties;
import com.techStack.authSys.util.HelperUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

/**
 * Validates bootstrap configuration before attempting Super Admin creation.
 * Ensures all required fields are present and properly formatted.
 */
@Slf4j
@Service
public class BootstrapValidationService {

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
    );

    private static final Pattern E164_PHONE_PATTERN = Pattern.compile(
            "^\\+?[1-9]\\d{1,14}$"
    );

    /**
     * Validates bootstrap configuration from app properties.
     *
     * @param config Application configuration properties
     * @return true if configuration is valid, false otherwise
     */
    public boolean validateBootstrapConfig(AppConfigProperties config) {
        log.debug("🔍 Validating bootstrap configuration...");

        // Check if configuration exists
        if (config == null) {
            log.error("❌ Bootstrap configuration is null");
            return false;
        }

        // Validate email
        String email = config.getSuperAdminEmail();
        if (!validateEmail(email)) {
            log.error("❌ Invalid or missing Super Admin email: {}",
                    HelperUtils.maskEmail(email));
            return false;
        }

        // Validate phone
        String phone = config.getSuperAdminPhone();
        if (!validatePhone(phone)) {
            log.error("❌ Invalid or missing Super Admin phone: {}",
                    maskPhone(phone));
            return false;
        }

        log.info("✅ Bootstrap configuration validated successfully");
        log.debug("  Email: {}", HelperUtils.maskEmail(email));
        log.debug("  Phone: {}", maskPhone(phone));

        return true;
    }

    /**
     * Validates email format.
     */
    private boolean validateEmail(String email) {
        if (StringUtils.isBlank(email)) {
            return false;
        }

        email = email.trim().toLowerCase();
        return EMAIL_PATTERN.matcher(email).matches();
    }

    /**
     * Validates phone format.
     * Accepts various formats and normalizes to E.164.
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

    /**
     * Normalizes phone number to E.164 format.
     * Handles Kenyan numbers specifically.
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

    /**
     * Masks phone for logging (GDPR compliance).
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
