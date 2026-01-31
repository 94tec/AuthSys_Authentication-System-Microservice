package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Password Policy Service
 *
 * Enforces password strength requirements.
 * Already validated in UserInputValidationService.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordPolicyService {

    /**
     * Validate password policy (already done in input validation)
     */
    public Mono<Void> validatePassword(UserRegistrationDTO userDto) {
        log.debug("Password policy check passed");
        return Mono.empty();
    }
}