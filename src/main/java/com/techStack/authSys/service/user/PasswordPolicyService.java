package com.techStack.authSys.service.user;

import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.service.CustomException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Password Policy Service
 *
 * Enforces business/security password policies beyond regex strength.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordPolicyService {

    private final PasswordHistoryService passwordHistoryService;
    private final BreachedPasswordService breachedPasswordService;
    private final DictionaryPasswordService dictionaryPasswordService;

    /**
     * Validate password against business/security policies.
     */
    public Mono<Void> validatePassword(UserRegistrationDTO userDto) {
        String password = userDto.getPassword();
        String uid = userDto.getUid();

        // ✅ Registration flow — no history yet
        if (uid == null) {
            return breachedPasswordService.isBreached(password)
                    .flatMap(breached -> breached
                            ? Mono.error(passwordError("Password appears in breach database", "ERROR_PASSWORD_BREACHED"))
                            : Mono.empty()
                    )
                    .then(dictionaryPasswordService.isCommonWord(password)
                            .flatMap(common -> common
                                    ? Mono.error(passwordError("Password is too common", "ERROR_PASSWORD_COMMON"))
                                    : Mono.empty()
                            ));
        }

        // ✅ Password change flow
        return passwordHistoryService.isPasswordReused(uid, password)
                .flatMap(reused -> reused
                        ? Mono.error(passwordError("Password has been used previously", "ERROR_PASSWORD_REUSED"))
                        : Mono.empty()
                )
                .then(breachedPasswordService.isBreached(password)
                        .flatMap(breached -> breached
                                ? Mono.error(passwordError("Password appears in breach database", "ERROR_PASSWORD_BREACHED"))
                                : Mono.empty()
                        ))
                .then(dictionaryPasswordService.isCommonWord(password)
                        .flatMap(common -> common
                                ? Mono.error(passwordError("Password is too common", "ERROR_PASSWORD_COMMON"))
                                : Mono.empty()
                        ))
                .doOnSuccess(v -> log.debug("✅ Password policy check passed for uid={}", uid)).then();
    }

    private CustomException passwordError(String message, String code) {
        return new CustomException(
                HttpStatus.BAD_REQUEST,
                message,
                "password",
                code
        );
    }
}

