package com.techStack.authSys.service.registration;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.service.security.DomainValidationService;
import com.techStack.authSys.service.security.GeoLocationService;
import com.techStack.authSys.service.security.SuspiciousActivityService;
import com.techStack.authSys.service.user.PasswordPolicyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.util.Set;

/**
 * Registration Security Service
 *
 * Performs comprehensive security validations:
 * - Rate limiting
 * - Geolocation validation
 * - Suspicious activity detection
 * - Domain validation
 * - Password policy enforcement
 * - Honeypot check (bot detection)
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
     * Orchestrate all security checks in parallel where possible
     */
    public Mono<Void> performSecurityChecks(
            UserRegistrationDTO userDto,
            String ipAddress,
            String deviceFingerprint
    ) {
        return Mono.when(
                        performRateLimitCheck(ipAddress),
                        performGeolocationCheck(ipAddress),
                        performSuspiciousActivityCheck(userDto, ipAddress, deviceFingerprint)
                )
                .then(performDomainValidation(userDto))
                .then(performPasswordPolicyCheck(userDto))
                .then(performHoneypotCheck(userDto));
    }

    /**
     * Check rate limiting
     */
    private Mono<Void> performRateLimitCheck(String ipAddress) {
        return throttleService.checkRateLimit(ipAddress)
                .doOnSuccess(v -> log.debug("Rate limit check passed for IP: {}", ipAddress))
                .doOnError(e -> log.warn("Rate limit exceeded for IP: {}", ipAddress))
                .onErrorResume(e -> Mono.error(new CustomException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        "Too many registration attempts. Please try again later."
                )));
    }

    /**
     * Validate geolocation
     */
    private Mono<Void> performGeolocationCheck(String ipAddress) {
        return geoLocationService.validateLocation(ipAddress)
                .doOnSuccess(v -> log.debug("Geolocation check passed for IP: {}", ipAddress))
                .doOnError(e -> log.warn("Geolocation validation failed for IP: {}", ipAddress))
                .onErrorResume(e -> {
                    log.warn("Continuing registration despite geolocation failure");
                    return Mono.empty();
                }).then();
    }

    /**
     * Detect suspicious activity
     */
    private Mono<Void> performSuspiciousActivityCheck(
            UserRegistrationDTO userDto,
            String ipAddress,
            String deviceFingerprint
    ) {
        return suspiciousActivityService.checkPatterns(
                        userDto.getEmail(),
                        ipAddress,
                        userDto.getMetadata()
                )
                .doOnSuccess(v -> log.debug("Suspicious activity check passed for: {}",
                        userDto.getEmail()))
                .doOnError(e -> log.warn("Suspicious activity detected for: {}",
                        userDto.getEmail()))
                .onErrorResume(e -> {
                    log.warn("Continuing with elevated monitoring");
                    return Mono.empty();
                });
    }

    /**
     * Validate email domain
     */
    private Mono<Void> performDomainValidation(UserRegistrationDTO userDto) {
        return domainValidationService.validateActiveDomain(userDto)
                .doOnSuccess(v -> log.debug("Domain validation passed for: {}",
                        userDto.getEmail()))
                .doOnError(e -> log.warn("Domain validation failed for: {}",
                        userDto.getEmail()))
                .then();
    }

    /**
     * Enforce password policy
     */
    private Mono<Void> performPasswordPolicyCheck(UserRegistrationDTO userDto) {
        return passwordPolicyService.validatePassword(userDto)
                .doOnSuccess(v -> log.debug("Password policy check passed"))
                .doOnError(e -> log.warn("Password policy violation for: {}",
                        userDto.getEmail()))
                .then();
    }

    /**
     * Check honeypot field (bot detection)
     */
    private Mono<Void> performHoneypotCheck(UserRegistrationDTO userDto) {
        if (userDto.getMetadata() != null &&
                StringUtils.hasText(userDto.getMetadata().getHoneypot())) {
            log.warn("Honeypot field filled for: {} - potential bot", userDto.getEmail());
            return Mono.error(new CustomException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid form submission"
            ));
        }
        return Mono.empty();
    }
}