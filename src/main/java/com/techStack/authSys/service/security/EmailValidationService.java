package com.techStack.authSys.service.security;

import com.techStack.authSys.config.core.EmailValidationConfig;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.domain.InvalidDomainException;
import com.techStack.authSys.exception.service.CustomException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static com.techStack.authSys.util.validation.HelperUtils.maskEmail;

/**
 * Email Validation Service
 *
 * ✅ FIXED:
 *  1. Injects DnsJavaResolver directly (not the interface) so hasARecord() is accessible.
 *  2. isDomainActive() uses dnsResolver.hasARecord() instead of InetAddress.getByName()
 *     — InetAddress uses system DNS which ignores your configured server and timeout.
 *  3. Constructor is explicit (no @RequiredArgsConstructor) because DnsJavaResolver
 *     throws a checked exception during construction.
 */
@Slf4j
@Service
public class EmailValidationService {

    private final DnsJavaResolver dnsResolver;          // ✅ Concrete type for hasARecord()
    private final EmailValidationConfig emailValidationConfig;
    private final Map<String, String> typoCache = new ConcurrentHashMap<>();

    /* ✅ FIXED: Explicit constructor */
    public EmailValidationService(
            DnsJavaResolver dnsResolver,
            EmailValidationConfig emailValidationConfig) {
        this.dnsResolver = dnsResolver;
        this.emailValidationConfig = emailValidationConfig;
    }

    /* =========================
       Full Validation Pipeline
       ========================= */

    /**
     * Complete email validation pipeline for registration.
     * Steps ordered cheapest → most expensive.
     */
    public Mono<Void> validateEmailForRegistration(UserRegistrationDTO userDto) {
        return Mono.fromCallable(() -> {
                    String email = userDto.getEmail();

                    // 1. Presence
                    validatePresence(email);

                    // 2. Normalise (mutates DTO so downstream sees clean email)
                    email = email.trim().toLowerCase();
                    userDto.setEmail(email);

                    // 3. Length
                    validateLength(email);

                    // 4. Syntax
                    validateSyntax(email);

                    // 5. Extract parts
                    String domain    = extractDomain(email);
                    String localPart = extractLocalPart(email);

                    // 6. Typo detection — before DNS to avoid wasted lookups
                    detectAndSuggestTypos(domain);

                    // 7. Blocked domain
                    validateNotBlockedDomain(domain);

                    // 8. Role address
                    validateNotRoleAddress(localPart);

                    // 9. DNS — most expensive, always last
                    validateDnsActive(domain);

                    log.info("✅ Email fully validated: {}", maskEmail(email));
                    return true;

                }).subscribeOn(Schedulers.boundedElastic())
                .then();
    }

    /**
     * Quick validation for non-critical paths (login hints, etc.).
     * Skips DNS entirely.
     */
    public boolean quickValidate(String email) {
        if (email == null || email.isBlank()) return false;
        try {
            email = email.trim().toLowerCase();
            validateLength(email);
            validateSyntax(email);
            String domain    = extractDomain(email);
            String localPart = extractLocalPart(email);
            if (emailValidationConfig.getBlockedDomains().contains(domain))  return false;
            if (emailValidationConfig.getRolePrefixes().contains(localPart)) return false;
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /* =========================
       Step 1 — Presence
       ========================= */

    private void validatePresence(String email) {
        if (email == null || email.isBlank()) {
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Email address is required", "email", "ERROR_EMAIL_REQUIRED");
        }
    }

    /* =========================
       Step 3 — Length
       ========================= */

    private void validateLength(String email) {
        if (email.length() > 254) {
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Email address is too long (max 254 characters)",
                    "email", "ERROR_EMAIL_TOO_LONG");
        }
        if (extractLocalPart(email).length() > 64) {
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Email local part is too long (max 64 characters)",
                    "email", "ERROR_EMAIL_LOCAL_TOO_LONG");
        }
    }

    /* =========================
       Step 4 — Syntax
       ========================= */

    private void validateSyntax(String email) {
        if (!emailValidationConfig.getEmailRegex().matcher(email).matches()) {
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Email address has invalid format",
                    "email", "ERROR_EMAIL_INVALID_FORMAT");
        }

        String local = extractLocalPart(email);

        if (local.startsWith(".") || local.endsWith(".")) {
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Email local part cannot start or end with a dot",
                    "email", "ERROR_EMAIL_DOT_POSITION");
        }
        if (local.contains("..")) {
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Email local part cannot contain consecutive dots",
                    "email", "ERROR_EMAIL_CONSECUTIVE_DOTS");
        }
    }

    /* =========================
       Step 6 — Typo Detection
       ========================= */

    private void detectAndSuggestTypos(String domain) {
        // Cache hit
        if (typoCache.containsKey(domain)) {
            String suggestion = typoCache.get(domain);
            if (suggestion != null) throwTypoException(domain, suggestion);
            return;
        }

        // Exact match in known providers — definitely correct
        if (emailValidationConfig.getKnownProviders().contains(domain)) {
            typoCache.put(domain, null);
            return;
        }

        // TLD typo (gmail.cmo)
        Optional<String> tldFix = checkTldTypo(domain);
        if (tldFix.isPresent()) {
            typoCache.put(domain, tldFix.get());
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    String.format("Did you mean @%s? '%s' appears to have a typo in the domain extension.",
                            tldFix.get(), domain),
                    "email", "ERROR_EMAIL_TLD_TYPO");
        }

        // Edit-distance check (gmgail.com → gmail.com = distance 2)
        Optional<String> closest = findClosestProvider(domain);
        if (closest.isPresent()) {
            typoCache.put(domain, closest.get());
            throwTypoException(domain, closest.get());
        }

        typoCache.put(domain, null); // No typo found
    }

    private Optional<String> checkTldTypo(String domain) {
        for (Map.Entry<String, String> entry : emailValidationConfig.getTldTypos().entrySet()) {
            if (domain.endsWith(entry.getKey())) {
                return Optional.of(domain.replace(entry.getKey(), entry.getValue()));
            }
        }
        return Optional.empty();
    }

    private Optional<String> findClosestProvider(String domain) {
        int bestDistance = Integer.MAX_VALUE;
        String bestMatch = null;

        for (String provider : emailValidationConfig.getKnownProviders()) {
            if (Math.abs(domain.length() - provider.length()) > 2) continue; // Skip obviously different

            int distance = optimizedLevenshtein(domain, provider);
            if (distance < bestDistance && distance <= emailValidationConfig.getMaxEditDistance()) {
                bestDistance = distance;
                bestMatch = provider;
                if (distance == 1) break; // Can't do better
            }
        }

        return Optional.ofNullable(bestMatch);
    }

    private void throwTypoException(String domain, String suggestion) {
        log.warn("🔤 Likely email typo: '{}' → suggest '{}'", domain, suggestion);
        throw new CustomException(HttpStatus.BAD_REQUEST,
                String.format("Did you mean @%s? '%s' looks like a misspelling. " +
                        "Please double-check your email address.", suggestion, domain),
                "email", "ERROR_EMAIL_TYPO_DETECTED");
    }

    /* =========================
       Step 7 — Blocked Domain
       ========================= */

    private void validateNotBlockedDomain(String domain) {
        if (emailValidationConfig.getBlockedDomains().contains(domain)) {
            log.warn("🚫 Blocked email domain: {}", domain);
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Email domain is not allowed for registration. Please use a valid personal or business email.",
                    "email", "ERROR_EMAIL_BLOCKED_DOMAIN");
        }
    }

    /* =========================
       Step 8 — Role Address
       ========================= */

    private void validateNotRoleAddress(String localPart) {
        if (emailValidationConfig.getRolePrefixes().contains(localPart.toLowerCase())) {
            log.warn("🚫 Role-based email rejected: {}", localPart);
            throw new CustomException(HttpStatus.BAD_REQUEST,
                    "Role-based email addresses (e.g. admin@, noreply@) cannot be used for registration",
                    "email", "ERROR_EMAIL_ROLE_ADDRESS");
        }
    }

    /* =========================
       Step 9 — DNS
       ========================= */

    private void validateDnsActive(String domain) {
        if (!emailValidationConfig.isDnsValidationEnabled()) {
            log.debug("DNS validation disabled — skipping for domain: {}", domain);
            return;
        }

        if (!isDomainActive(domain)) {
            throw new InvalidDomainException("Invalid or inactive email domain: " + domain);
        }
    }

    /**
     * ✅ Uses DnsJavaResolver for both checks. dnsResolver.hasARecord(domain)
     *   — uses your configured DNS server (8.8.8.8).
     *   — respects your configured timeout.
     *   — consistent with MX lookup behaviour.
     */
    private boolean isDomainActive(String domain) {
        try {
            // 1. MX lookup — preferred (means domain can receive mail)
            List<String> mxRecords = dnsResolver.resolveMxRecords(domain);
            if (!mxRecords.isEmpty()) {
                log.debug("✅ Domain {} has {} MX record(s)", domain, mxRecords.size());
                return true;
            }

            // 2. A record fallback — domain exists but may not have MX configured
            boolean hasA = dnsResolver.hasARecord(domain);  // ✅ Uses DnsJavaResolver
            if (hasA) {
                log.debug("⚠️ Domain {} has no MX but has A record — allowing", domain);
                return true;
            }

            log.warn("❌ Domain {} has no MX and no A record — rejecting", domain);
            return false;

        } catch (Exception e) {
            log.warn("DNS validation error for domain {}: {}", domain, e.getMessage());
            return false;
        }
    }

    /* =========================
       Helpers
       ========================= */

    private String extractDomain(String email) {
        int at = email.lastIndexOf('@');
        if (at < 0) throw new CustomException(HttpStatus.BAD_REQUEST,
                "Invalid email format", "email", "ERROR_EMAIL_INVALID");
        return email.substring(at + 1).trim().toLowerCase();
    }

    private String extractLocalPart(String email) {
        int at = email.lastIndexOf('@');
        if (at < 0) throw new CustomException(HttpStatus.BAD_REQUEST,
                "Invalid email format", "email", "ERROR_EMAIL_INVALID");
        return email.substring(0, at).trim();
    }

    /* =========================
       Optimized Levenshtein
       ========================= */

    /** O(min(m,n)) space using rolling arrays. */
    private int optimizedLevenshtein(String a, String b) {
        if (a.length() > b.length()) { String t = a; a = b; b = t; } // ensure a is shorter

        int m = a.length(), n = b.length();
        int[] prev = new int[n + 1];
        int[] curr = new int[n + 1];

        for (int j = 0; j <= n; j++) prev[j] = j;

        for (int i = 1; i <= m; i++) {
            curr[0] = i;
            for (int j = 1; j <= n; j++) {
                curr[j] = a.charAt(i - 1) == b.charAt(j - 1)
                        ? prev[j - 1]
                        : 1 + Math.min(prev[j - 1], Math.min(prev[j], curr[j - 1]));
            }
            int[] tmp = prev; prev = curr; curr = tmp;
        }

        return prev[n];
    }
}