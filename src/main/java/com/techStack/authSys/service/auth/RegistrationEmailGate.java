package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.service.registration.DuplicateEmailCheckService;
import com.techStack.authSys.service.security.EmailValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static com.techStack.authSys.util.validation.HelperUtils.maskEmail;

/**
 * Registration Email Gate
 * Usage:
 *   return emailGate.validate(userDto)
 *       .then(authService.registerUser(userDto, exchange));
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationEmailGate {

    private final EmailValidationService emailValidationService;
    private final DuplicateEmailCheckService duplicateEmailCheckService;

    /**
     * Full pre-registration email gate.
     *
     * Checks (in order):
     *  1. Full email validation (syntax, typo detection, DNS, etc.)
     *  2. Duplicate email check (Redis + Firebase)
     */
    public Mono<Void> validate(UserRegistrationDTO dto) {
        String email = dto.getEmail();
        log.info("Starting registration validation for: {}", maskEmail(email));

        return emailValidationService.validateEmailForRegistration(dto)
                .then(duplicateEmailCheckService.checkDuplicateEmail(dto))
                .then(Mono.fromRunnable(() ->
                        log.info("✅ Registration validation passed for: {}", maskEmail(email))
                ))
                .then()
                .onErrorResume(this::handleValidationError);
    }

    /**
     * Optional: Quick validation for other use cases (password reset, etc.)
     */
    public Mono<Boolean> quickValidate(String email) {
        return Mono.fromCallable(() -> emailValidationService.quickValidate(email))
                .onErrorReturn(false);
    }

    /**
     * Convert different exception types to appropriate CustomException
     */
    private Mono<Void> handleValidationError(Throwable error) {
        log.error("❌ Validation error type: {} | message: {}",
                error.getClass().getSimpleName(), error.getMessage(), error);
        if (error instanceof com.techStack.authSys.exception.email.EmailAlreadyExistsException) {
            return Mono.error(new CustomException(
                    HttpStatus.CONFLICT,
                    "An account with this email already exists",
                    "email",
                    "ERROR_EMAIL_ALREADY_REGISTERED"
            ));
        }

        // Re-throw any CustomException from email validation service
        if (error instanceof CustomException) {
            return Mono.error(error);
        }

        // Wrap any other exceptions
        return Mono.error(new CustomException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Registration validation failed",
                "global",
                "ERROR_REGISTRATION_VALIDATION"
        ));
    }

    /**
     * Pre-flight check: Validate email only (without duplicate check)
     * Useful for frontend validation before form submission
     */
    public Mono<Boolean> preValidateEmail(String email) {
        return Mono.fromCallable(() -> emailValidationService.quickValidate(email))
                .doOnSuccess(valid -> {
                    if (valid) {
                        log.debug("✅ Pre-validation passed for: {}", maskEmail(email));
                    } else {
                        log.debug("❌ Pre-validation failed for: {}", maskEmail(email));
                    }
                })
                .onErrorReturn(false);
    }
}