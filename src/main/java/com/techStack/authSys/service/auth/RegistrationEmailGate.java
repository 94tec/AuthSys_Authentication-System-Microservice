package com.techStack.authSys.service.auth;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.security.DomainValidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Registration Email Gate
 *
 * Drop this into your AuthService.registerUser() chain BEFORE
 * any user object is created or persisted.
 *
 * Usage:
 *   return emailGate.validate(userDto)
 *       .then(authService.registerUser(userDto, exchange));
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationEmailGate {

    private final DomainValidationService domainValidationService;
    private final FirestoreUserRepository userRepository;

    /**
     * Full pre-registration email gate.
     *
     * Checks (in order):
     *  1. Syntax + domain validity   → DomainValidationService
     *  2. Duplicate email in DB      → userRepository
     */
    public Mono<Void> validate(UserRegistrationDTO dto) {
        return domainValidationService.validateActiveDomain(dto)
                .then(checkEmailNotAlreadyRegistered(dto.getEmail()));
    }

    /**
     * Reject if email already exists in the database.
     * (Prevents duplicate accounts AND leaking user existence via timing.)
     */
    private Mono<Void> checkEmailNotAlreadyRegistered(String email) {
        return userRepository.findByEmail(email)
                .flatMap(existingUser -> Mono.<Void>error(
                        new CustomException(
                                HttpStatus.CONFLICT,
                                "An account with this email already exists",
                                "email",
                                "ERROR_EMAIL_ALREADY_REGISTERED"
                        )
                ))
                .switchIfEmpty(Mono.empty());  // ✅ Not found = proceed
    }
}
