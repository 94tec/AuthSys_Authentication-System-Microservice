package com.techStack.authSys.security;

import com.techStack.authSys.exception.AccountDisabledException;
import com.techStack.authSys.exception.AccountLockedException;
import com.techStack.authSys.exception.AccountNotFoundException;
import com.techStack.authSys.exception.EmailNotVerifiedException;
import com.techStack.authSys.models.User;
import com.techStack.authSys.service.AuditLogService;
import com.techStack.authSys.repository.AccountLockService;
import com.techStack.authSys.service.FirebaseServiceAuth;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccountStatusChecker {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AccountLockService accountLockService;
    private final AuditLogService auditLogService;

    /**
     * Checks if the user account is active, not locked, and email is verified before authentication.
     */
    public Mono<User> checkAccountStatus(String email) {
        log.info("Checking account status for email: {}", email);

        return firebaseServiceAuth.findByEmail(email)
                .doOnSuccess(user -> log.info("Found user: {}", user.getEmail()))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("Account not found for email: {}", email);
                    return Mono.error(new AccountNotFoundException("User not found"));
                }))
                .flatMap(user -> validateAccount(user)
                        .thenReturn(user))
                .doOnError(e -> log.error("Account status check failed for email {}: {}", email, e.getMessage()));
    }

    /**
     * Performs all account validation checks.
     */
    private Mono<Void> validateAccount(User user) {
        return Mono.when(
                validateAccountActive(user),
                validateEmailVerified(user),
                validateAccountNotLocked(user)
        );
    }

    /**
     * Ensures the user account is active.
     */
    private Mono<Void> validateAccountActive(User user) {
        if (!user.isEnabled()) {
            log.warn("Account is disabled for user ID: {}. Login attempt blocked.", user.getId());
            auditLogService.logSecurityEvent("DISABLED_ACCOUNT_ACCESS_ATTEMPT", user.getId(),
                    "Attempted login to disabled account");
            return Mono.error(new AccountDisabledException("Account is disabled"));
        }
        return Mono.empty();
    }

    /**
     * Ensures the user email is verified.
     */
    private Mono<Void> validateEmailVerified(User user) {
        if (!user.isEmailVerified()) {
            log.warn("Email not verified for user ID: {}. Login attempt blocked.", user.getId());
            auditLogService.logSecurityEvent("UNVERIFIED_EMAIL_LOGIN_ATTEMPT", user.getId(),
                    "Attempted login with unverified email");
            return Mono.error(new EmailNotVerifiedException("Email not verified"));
        }
        return Mono.empty();
    }

    /**
     * Ensures the user account is not locked.
     */
    private Mono<Void> validateAccountNotLocked(User user) {
        if (accountLockService.isAccountLocked(user.getId())) {
            log.warn("Account is locked for user ID: {}. Login attempt blocked.", user.getId());
            auditLogService.logSecurityEvent("ACCOUNT_LOCKED_ACCESS_ATTEMPT", user.getId(),
                    "Attempted login to locked account");
            return Mono.error(new AccountLockedException("Account temporarily locked"));
        }
        return Mono.empty();
    }
}
