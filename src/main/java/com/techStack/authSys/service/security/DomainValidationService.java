package com.techStack.authSys.service.security;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.domain.InvalidDomainException;
import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.InetAddress;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static com.techStack.authSys.util.validation.HelperUtils.maskEmail;

/**
 * Domain Validation Service
 *
 * ✅ ENHANCED: Full email validation pipeline
 *  1. Syntax check  (regex)
 *  2. Disposable / blocked domain check
 *  3. DNS / MX record check
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DomainValidationService {

    private final DnsResolver dnsResolver;

    /* =========================
       Regex
       ========================= */

    /**
     * RFC 5322-compatible email regex.
     * Rejects consecutive dots, leading/trailing dots in local part, etc.
     */
    private static final Pattern EMAIL_REGEX = Pattern.compile(
            "^(?![.])(?!.*\\.\\.)[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}"
                    + "@"
                    + "[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?"
                    + "(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*"
                    + "\\.[a-zA-Z]{2,}$"
    );

    /* =========================
       Blocked Domains
       ========================= */

    /**
     * Disposable / throwaway email providers to block.
     * Extend this list as needed.
     */
    private static final Set<String> BLOCKED_DOMAINS = Set.of(
            // Disposable providers
            "mailinator.com", "guerrillamail.com", "temp-mail.org",
            "throwam.com",    "yopmail.com",        "trashmail.com",
            "fakeinbox.com",  "sharklasers.com",    "guerrillamailblock.com",
            "grr.la",         "guerrillamail.info",  "spam4.me",
            "tempmail.com",   "dispostable.com",    "10minutemail.com",
            "mailnull.com",   "maildrop.cc",        "spamgourmet.com",
            "getnada.com",    "tempr.email",        "discard.email",
            "spamex.com",     "mailexpire.com",     "spamfree24.org",
            "tempe-mail.com", "tmpmail.net",        "mohmal.com",

            // Role-based / generic addresses that should not register
            // (block by prefix logic — handled in isRoleAddress)

            // Known test / example domains (RFC 2606)
            "example.com", "example.net", "example.org",
            "test.com",    "invalid",     "localhost"
    );

    /**
     * Role-based address prefixes (e.g. admin@, noreply@) that are
     * typically not real user mailboxes.
     */
    private static final Set<String> ROLE_PREFIXES = Set.of(
            "admin", "administrator", "postmaster", "hostmaster", "webmaster",
            "abuse", "noreply", "no-reply", "mailer-daemon", "root",
            "info", "support", "contact", "sales", "marketing",
            "security", "help", "billing", "team", "staff"
    );

    /* =========================
       Full Pipeline
       ========================= */

    /**
     * Run the complete email validation pipeline for registration.
     *
     * Order:
     *  1. Null / blank
     *  2. Length limits
     *  3. Regex syntax
     *  4. Blocked / disposable domain
     *  5. Role-based prefix
     *  6. DNS MX / A record
     */
    public Mono<Void> validateActiveDomain(UserRegistrationDTO userDto) {
        return Mono.fromCallable(() -> {
                    String email = userDto.getEmail();

                    // 1. Null / blank
                    if (email == null || email.isBlank()) {
                        throw new CustomException(
                                HttpStatus.BAD_REQUEST,
                                "Email address is required",
                                "email",
                                "ERROR_EMAIL_REQUIRED"
                        );
                    }

                    // Normalise
                    email = email.trim().toLowerCase();

                    // 2. Length
                    validateLength(email);

                    // 3. Regex
                    validateSyntax(email);

                    // 4. Blocked domain
                    String domain = extractDomain(email);
                    validateNotBlockedDomain(domain);

                    // 5. Role address
                    validateNotRoleAddress(email);

                    // 6. DNS
                    validateDnsActive(domain);

                    log.info("✅ Email fully validated: {}", maskEmail(email));
                    return true;

                }).subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /* =========================
       Step 2 – Length
       ========================= */

    private void validateLength(String email) {
        if (email.length() > 254) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Email address is too long (max 254 characters)",
                    "email",
                    "ERROR_EMAIL_TOO_LONG"
            );
        }

        String local = email.substring(0, email.lastIndexOf('@'));
        if (local.length() > 64) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Email local part is too long (max 64 characters)",
                    "email",
                    "ERROR_EMAIL_LOCAL_TOO_LONG"
            );
        }
    }

    /* =========================
       Step 3 – Syntax
       ========================= */

    private void validateSyntax(String email) {
        if (!EMAIL_REGEX.matcher(email).matches()) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Email address has invalid format",
                    "email",
                    "ERROR_EMAIL_INVALID_FORMAT"
            );
        }

        // Extra checks the regex does not cover
        String local = email.substring(0, email.lastIndexOf('@'));

        if (local.startsWith(".") || local.endsWith(".")) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Email local part cannot start or end with a dot",
                    "email",
                    "ERROR_EMAIL_DOT_POSITION"
            );
        }

        if (local.contains("..")) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Email local part cannot contain consecutive dots",
                    "email",
                    "ERROR_EMAIL_CONSECUTIVE_DOTS"
            );
        }
    }

    /* =========================
       Step 4 – Blocked Domain
       ========================= */

    private void validateNotBlockedDomain(String domain) {
        if (BLOCKED_DOMAINS.contains(domain)) {
            log.warn("🚫 Blocked email domain used: {}", domain);
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Email domain is not allowed for registration. Please use a valid personal or business email.",
                    "email",
                    "ERROR_EMAIL_BLOCKED_DOMAIN"
            );
        }
    }

    /* =========================
       Step 5 – Role Address
       ========================= */

    private void validateNotRoleAddress(String email) {
        String local = email.substring(0, email.lastIndexOf('@')).toLowerCase();

        if (ROLE_PREFIXES.contains(local)) {
            log.warn("🚫 Role-based email address rejected: {}", maskEmail(email));
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Role-based email addresses (e.g. admin@, noreply@) cannot be used for registration",
                    "email",
                    "ERROR_EMAIL_ROLE_ADDRESS"
            );
        }
    }

    /* =========================
       Step 6 – DNS
       ========================= */

    /**
     * Domain is active if it has MX records or resolves via A record.
     * (your original logic, unchanged)
     */
    private void validateDnsActive(String domain) {
        if (!isDomainActive(domain)) {
            throw new InvalidDomainException(
                    "Invalid or inactive email domain: " + domain
            );
        }
    }

    private boolean isDomainActive(String domain) {
        try {
            // 1) MX lookup
            List<String> mxRecords = dnsResolver.resolveMxRecords(domain);
            if (!mxRecords.isEmpty()) {
                log.debug("Domain {} has MX records: {}", domain, mxRecords);
                return true;
            }

            // 2) A record fallback
            InetAddress address = InetAddress.getByName(domain);
            if (address != null) {
                log.debug("Domain {} resolves to IP: {}", domain, address.getHostAddress());
                return true;
            }

            log.warn("Domain {} has no MX and no A record", domain);
            return false;

        } catch (Exception e) {
            log.warn("Domain lookup failed for {}: {}", domain, e.getMessage());
            return false;
        }
    }

    /* =========================
       Helpers
       ========================= */

    private String extractDomain(String email) {
        if (email == null || !email.contains("@")) {
            throw new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid email format",
                    "email",
                    "ERROR_EMAIL_INVALID"
            );
        }
        return email.substring(email.lastIndexOf('@') + 1).trim().toLowerCase();
    }

}