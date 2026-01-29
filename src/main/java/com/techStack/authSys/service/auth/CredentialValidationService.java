package com.techStack.authSys.service.auth;

import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.security.validation.AccountStatusChecker;
import com.techStack.authSys.service.user.PasswordExpiryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Handles credential validation and user account checks.
 * Validates passwords, checks account status, and verifies password expiry.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialValidationService {

    private final FirebaseServiceAuth firebaseServiceAuth;
    private final AccountStatusChecker accountStatusChecker;
    private final PasswordExpiryService passwordExpiryService;

    /**
     * Validates user credentials and performs all account checks.
     *
     * @param email User email
     * @param password User password
     * @return Mono of User with full details and permissions
     */
    public Mono<User> validateAndFetchUser(String email, String password) {
        return fetchUserRecord(email)
                .flatMap(userRecord -> performValidationChain(email, password, userRecord))
                .onErrorMap(this::translateException)
                .doOnError(e -> {
                    if (e instanceof AuthException) {
                        firebaseServiceAuth.logAuthFailure(email, e);
                    }
                })
                .doOnSuccess(user -> firebaseServiceAuth.logAuthSuccess(email));
    }

    /**
     * Fetches user record from Firebase Auth.
     */
    private Mono<UserRecord> fetchUserRecord(String email) {
        return firebaseServiceAuth.getUserRecord(email)
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * Performs the complete validation chain:
     * 1. Validate credentials
     * 2. Check account status (disabled, locked, etc.)
     * 3. Check password expiry
     * 4. Fetch full user details with permissions
     */
    private Mono<User> performValidationChain(String email, String password, UserRecord userRecord) {
        return validateCredentials(email, password)
                .then(checkAccountStatus(email))
                .then(checkPasswordExpiry(userRecord.getUid(), password))
                .then(fetchUserWithPermissions(userRecord.getUid()));
    }

    /**
     * Validates user credentials against Firebase Auth.
     */
    private Mono<Void> validateCredentials(String email, String password) {
        return firebaseServiceAuth.validateCredentials(email, password)
                .doOnSuccess(v -> log.debug("Credentials validated for: {}", email))
                .doOnError(e -> log.warn("Invalid credentials for: {}", email));
    }

    /**
     * Checks if account is active and not locked.
     */
    private Mono<Void> checkAccountStatus(String email) {
        return accountStatusChecker.checkAccountStatus(email)
                .doOnSuccess(v -> log.debug("Account status check passed for: {}", email))
                .doOnError(e -> log.warn("Account status check failed for: {}", email, e)).then();
    }

    /**
     * Verifies that password hasn't expired.
     */
    private Mono<Void> checkPasswordExpiry(String userId, String password) {
        return passwordExpiryService.checkPasswordExpiry(userId, password)
                .doOnSuccess(v -> log.debug("Password expiry check passed for user: {}", userId))
                .doOnError(e -> log.warn("Password expired for user: {}", userId));
    }

    /**
     * Fetches complete user details including roles and permissions.
     */
    private Mono<User> fetchUserWithPermissions(String userId) {
        return firebaseServiceAuth.fetchUserDetailsWithPermissions(userId)
                .doOnSuccess(user -> log.debug("Fetched user details for: {}", user.getEmail()));
    }

    /**
     * Translates Firebase exceptions to AuthException.
     */
    private Throwable translateException(Throwable e) {
        if (e instanceof AuthException) {
            return e;
        }
        return firebaseServiceAuth.translateFirebaseException(e);
    }
}
