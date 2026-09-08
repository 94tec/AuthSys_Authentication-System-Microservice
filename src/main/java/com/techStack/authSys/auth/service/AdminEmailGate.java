package com.techStack.authSys.auth.service;

import com.techStack.authSys.auth.exception.EmailAlreadyExistsException;
import com.techStack.authSys.identity.service.DuplicateEmailCheckService;
import com.techStack.authSys.identity.service.EmailValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static com.techStack.authSys.common.util.HelperUtils.maskEmail;

/**
 * Admin / Staff Email Gate
 *
 * Pre-creation email gate for staff onboarding (OPERATOR, MANAGER, ADMIN).
 * Mirrors RegistrationEmailGate's two-step chain, but works on a raw email
 * string since staff creation carries a UserDTO, not a UserRegistrationDTO:
 *
 *  1. Full format validation (presence, length, syntax, typo detection,
 *     blocked domain, role address, DNS) via EmailValidationService.
 *  2. Duplicate check (Redis + Firebase) via DuplicateEmailCheckService.
 *
 * This replaces the old static AdminUserValidator.validateEmailAvailability(
 * cacheService, email), which only checked Redis and skipped format/typo/DNS
 * validation entirely — staff emails now go through the same scrutiny as
 * self-registration.
 *
 * Usage (in AdminService.createStaffUser):
 *   return adminEmailGate.validate(userDto.getEmail())
 *       .flatMap(normalizedEmail -> {
 *           userDto.setEmail(normalizedEmail);
 *           ... build staffUser, createStaffInFirebase, etc ...
 *       });
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminEmailGate {

    private final EmailValidationService emailValidationService;
    private final DuplicateEmailCheckService duplicateEmailCheckService;

    /**
     * Runs full format validation, then a duplicate check.
     * Emits the normalized (trimmed + lowercased) email on success.
     * Errors with the underlying CustomException/InvalidDomainException from
     * EmailValidationService on bad format, or EmailAlreadyExistsException if taken.
     */
    public Mono<String> validate(String rawEmail) {
        log.info("Starting staff email gate for: {}", maskEmail(rawEmail));
        return emailValidationService.validateEmail(rawEmail)
                .flatMap(normalizedEmail ->
                        duplicateEmailCheckService.checkEmailAvailability(normalizedEmail)
                                .flatMap(available -> {
                                    if (!available) {
                                        log.warn("🚫 Staff email already registered: {}",
                                                maskEmail(normalizedEmail));
                                        return Mono.error(new EmailAlreadyExistsException(normalizedEmail));
                                    }
                                    return Mono.just(normalizedEmail);
                                })
                )
                .doOnSuccess(email ->
                        log.info("✅ Staff email gate passed for: {}", maskEmail(email)));
    }

    /**
     * Availability-only check (no format/typo/DNS validation) — kept for callers
     * that already validated format elsewhere and just need the duplicate check.
     */
    public Mono<Boolean> validateAvailability(String email) {
        log.info("Checking staff email availability for: {}", maskEmail(email));
        return duplicateEmailCheckService.checkEmailAvailability(email)
                .doOnSuccess(available -> {
                    if (available) {
                        log.info("✅ Staff email available: {}", maskEmail(email));
                    } else {
                        log.warn("🚫 Staff email already registered: {}", maskEmail(email));
                    }
                });
    }
}