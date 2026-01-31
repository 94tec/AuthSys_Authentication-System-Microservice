package com.techStack.authSys.service.security;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Suspicious Activity Service
 *
 * Detects and prevents suspicious registration patterns:
 * - Blacklisted IPs and emails
 * - Rate limiting per IP
 * - Honeypot detection
 * - Disposable email detection
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SuspiciousActivityService {

    private final Clock clock;

    /* =========================
       Configuration
       ========================= */

    @Value("${security.suspicious-activity.registration-cooldown-minutes:10}")
    private int cooldownMinutes;

    @Value("${security.suspicious-activity.check-localhost:false}")
    private boolean checkLocalhost;

    /* =========================
       Blacklists (Replace with Redis/DB)
       ========================= */

    private static final Set<String> BLACKLISTED_IPS = Set.of(
            "192.168.1.100",
            "10.0.0.50"
    );

    private static final Set<String> BLACKLISTED_EMAILS = Set.of(
            "test@spam.com",
            "fake@mailinator.com"
    );

    private static final Set<String> DISPOSABLE_DOMAINS = Set.of(
            "mailinator.com",
            "10minutemail.com",
            "guerrillamail.com",
            "throwaway.email"
    );

    /* =========================
       Rate Limiting
       ========================= */

    private final Map<String, Instant> recentRegistrations = new ConcurrentHashMap<>();

    /* =========================
       Pattern Checking
       ========================= */

    /**
     * Check for suspicious registration patterns
     */
    public Mono<Void> checkPatterns(
            String email,
            String ipAddress,
            UserRegistrationDTO.RegistrationMetadata metadata
    ) {
        return Mono.fromRunnable(() -> {
                    // Skip localhost during testing if configured
                    if (!checkLocalhost && isLocalhost(ipAddress)) {
                        log.debug("Skipping suspicious activity check for localhost IP: {}", ipAddress);
                        return;
                    }

                    // Check blacklists
                    checkBlacklistedIp(ipAddress);
                    checkBlacklistedEmail(email);

                    // Check disposable email
                    checkDisposableEmail(email);

                    // Check honeypot
                    checkHoneypot(metadata);

                    // Check rate limiting
                    checkRateLimit(ipAddress);

                    log.debug("Suspicious activity check passed for email: {}", email);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnError(e -> log.error("Suspicious activity check failed for email: {}", email, e))
                .onErrorResume(e -> Mono.error(
                        e instanceof CustomException ? e :
                                new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Error detecting suspicious activity")
                ))
                .then();
    }

    /* =========================
       Individual Checks
       ========================= */

    /**
     * Check if IP is blacklisted
     */
    private void checkBlacklistedIp(String ipAddress) {
        if (BLACKLISTED_IPS.contains(ipAddress)) {
            log.warn("🚫 Blacklisted IP detected: {}", ipAddress);
            throw new CustomException(
                    HttpStatus.FORBIDDEN,
                    "Suspicious IP detected"
            );
        }
    }

    /**
     * Check if email is blacklisted
     */
    private void checkBlacklistedEmail(String email) {
        if (BLACKLISTED_EMAILS.contains(email)) {
            log.warn("🚫 Blacklisted email detected: {}", email);
            throw new CustomException(
                    HttpStatus.FORBIDDEN,
                    "Suspicious email detected"
            );
        }
    }

    /**
     * Check if email is from disposable domain
     */
    private void checkDisposableEmail(String email) {
        String domain = extractDomain(email);

        if (DISPOSABLE_DOMAINS.contains(domain.toLowerCase())) {
            log.warn("🚫 Disposable email domain detected: {}", domain);
            throw new CustomException(
                    HttpStatus.FORBIDDEN,
                    "Disposable email addresses are not allowed"
            );
        }
    }

    /**
     * Check if honeypot was triggered
     */
    private void checkHoneypot(UserRegistrationDTO.RegistrationMetadata metadata) {
        if (metadata != null &&
                metadata.getHoneypot() != null &&
                !metadata.getHoneypot().isEmpty()) {

            log.warn("🚫 Honeypot triggered - potential bot detected");
            throw new CustomException(
                    HttpStatus.FORBIDDEN,
                    "Suspicious activity detected"
            );
        }
    }

    /**
     * Check rate limiting per IP
     */
    private void checkRateLimit(String ipAddress) {
        Instant now = clock.instant();
        Duration cooldown = Duration.ofMinutes(cooldownMinutes);

        // Clean up expired entries
        cleanupExpiredEntries(now, cooldown);

        // Check if IP recently registered
        Instant lastAttempt = recentRegistrations.get(ipAddress);

        if (lastAttempt != null) {
            Duration timeSinceLastAttempt = Duration.between(lastAttempt, now);

            if (timeSinceLastAttempt.compareTo(cooldown) < 0) {
                long minutesRemaining = cooldown.minus(timeSinceLastAttempt).toMinutes();

                log.warn("🚫 Too many registrations from IP: {} (cooldown: {} minutes remaining)",
                        ipAddress, minutesRemaining);

                throw new CustomException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        String.format("Too many registration attempts. Please try again in %d minutes.",
                                minutesRemaining)
                );
            }
        }

        // Register this attempt
        recentRegistrations.put(ipAddress, now);
        log.debug("Registered attempt from IP: {} at {}", ipAddress, now);
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Check if IP is localhost
     */
    private boolean isLocalhost(String ipAddress) {
        return "127.0.0.1".equals(ipAddress) ||
                "::1".equals(ipAddress) ||
                "localhost".equalsIgnoreCase(ipAddress);
    }

    /**
     * Extract domain from email
     */
    private String extractDomain(String email) {
        if (email == null || !email.contains("@")) {
            return "";
        }
        return email.substring(email.indexOf("@") + 1);
    }

    /**
     * Clean up expired entries from rate limit map
     */
    private void cleanupExpiredEntries(Instant now, Duration cooldown) {
        Iterator<Map.Entry<String, Instant>> iterator =
                recentRegistrations.entrySet().iterator();

        while (iterator.hasNext()) {
            Map.Entry<String, Instant> entry = iterator.next();
            Duration age = Duration.between(entry.getValue(), now);

            if (age.compareTo(cooldown) > 0) {
                iterator.remove();
                log.trace("Removed expired entry for IP: {}", entry.getKey());
            }
        }
    }
}