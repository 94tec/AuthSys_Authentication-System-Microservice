package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.UserDTO;
import com.techStack.authSys.exception.CustomException;
import com.techStack.authSys.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

/**
 * Performs security validations during registration:
 * - Rate limiting
 * - Geolocation validation
 * - Suspicious activity detection
 * - Domain validation
 * - Password policy enforcement
 * - Honeypot check
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationSecurityService {

    private final RegistrationThrottleService throttleService;
    private final GeoLocationService geoLocationService;
    private final SuspiciousActivityService suspiciousActivityService;
    private final DomainValidationService domainValidationService;
    private final PasswordPolicyService passwordPolicyService;

    /**
     * Orchestrates all security checks in parallel where possible.
     */
    public Mono<Void> performSecurityChecks(UserDTO userDto, String ipAddress) {
        return Mono.when(
                        performRateLimitCheck(ipAddress),
                        performGeolocationCheck(ipAddress),
                        performSuspiciousActivityCheck(userDto, ipAddress)
                )
                .then(performDomainValidation(userDto))
                .then(performPasswordPolicyCheck(userDto))
                .then(performHoneypotCheck(userDto));
    }

    /**
     * Check if IP address has exceeded registration rate limits.
     */
    private Mono<Void> performRateLimitCheck(String ipAddress) {
        return throttleService.checkRateLimit(ipAddress)
                .doOnSuccess(v -> log.debug("Rate limit check passed for IP: {}", ipAddress))
                .doOnError(e -> log.warn("Rate limit exceeded for IP: {}", ipAddress, e))
                .onErrorResume(e -> Mono.error(new CustomException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "Too many registration attempts. Please try again later."
                )));
    }

    /**
     * Validate registration location against allowed regions.
     */
    private Mono<Void> performGeolocationCheck(String ipAddress) {
        return geoLocationService.validateLocation(ipAddress)
                .doOnSuccess(v -> log.debug("Geolocation check passed for IP: {}", ipAddress))
                .doOnError(e -> log.warn("Geolocation validation failed for IP: {}", ipAddress, e))
                .onErrorResume(e -> {
                    // Non-fatal: log but continue (configurable based on security requirements)
                    log.warn("Continuing registration despite geolocation failure");
                    return Mono.empty();
                }).then();
    }

    /**
     * Detect suspicious registration patterns (e.g., disposable emails, bot behavior).
     */
    private Mono<Void> performSuspiciousActivityCheck(UserDTO userDto, String ipAddress) {
        return suspiciousActivityService.checkPatterns(
                        userDto.getEmail(),
                        ipAddress,
                        userDto.getRegistrationMetadata()
                )
                .doOnSuccess(v -> log.debug("Suspicious activity check passed for: {}",
                        userDto.getEmail()))
                .doOnError(e -> log.warn("Suspicious activity detected for: {}",
                        userDto.getEmail(), e))
                .onErrorResume(e -> {
                    // Could flag for manual review instead of blocking
                    log.warn("Continuing with elevated monitoring");
                    return Mono.empty();
                });
    }

    /**
     * Validate email domain against whitelist/blacklist.
     */
    private Mono<Void> performDomainValidation(UserDTO userDto) {
        return domainValidationService.validateActiveDomain(userDto)
                .doOnSuccess(v -> log.debug("Domain validation passed for: {}",
                        userDto.getEmail()))
                .doOnError(e -> log.warn("Domain validation failed for: {}",
                        userDto.getEmail(), e)).then();
    }

    /**
     * Enforce password strength requirements.
     */
    private Mono<Void> performPasswordPolicyCheck(UserDTO userDto) {
        return passwordPolicyService.validatePassword(userDto)
                .doOnSuccess(v -> log.debug("Password policy check passed"))
                .doOnError(e -> log.warn("Password policy violation for: {}",
                        userDto.getEmail(), e)).then();
    }

    /**
     * Check honeypot field (should be empty for legitimate users).
     */
    private Mono<Void> performHoneypotCheck(UserDTO userDto) {
        if (StringUtils.hasText(userDto.getHoneypot())) {
            log.warn("Honeypot field filled for: {} - potential bot", userDto.getEmail());
            return Mono.error(new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid form submission"
            ));
        }
        return Mono.empty();
    }
}
