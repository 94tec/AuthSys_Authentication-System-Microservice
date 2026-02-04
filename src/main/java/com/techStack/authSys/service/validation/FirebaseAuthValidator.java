package com.techStack.authSys.service.validation;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.config.intergration.FirebaseConfig;
import com.techStack.authSys.exception.auth.AuthException;
import com.techStack.authSys.exception.auth.AuthenticationException;
import com.techStack.authSys.exception.auth.FirebaseRestAuthException;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * Firebase Authentication Validator
 *
 * Responsibilities:
 * - Credential validation
 * - Firebase REST API authentication
 * - Authentication error translation
 * - Auth logging
 */
@Component
public class FirebaseAuthValidator {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseAuthValidator.class);

    private final FirebaseAuth firebaseAuth;
    private final FirebaseConfig firebaseConfig;
    private final WebClient webClient;

    public FirebaseAuthValidator(FirebaseAuth firebaseAuth, FirebaseConfig firebaseConfig) {
        this.firebaseAuth = firebaseAuth;
        this.firebaseConfig = firebaseConfig;
        this.webClient = WebClient.create();
    }

    // ============================================================================
    // CREDENTIAL VALIDATION
    // ============================================================================

    /**
     * Validates user credentials using Firebase
     */
    public Mono<Void> validateCredentials(String email, String password) {
        return getUserRecord(email)
                .flatMap(userRecord -> signInWithFirebase(email, password))
                .onErrorMap(this::translateFirebaseException);
    }

    /**
     * Gets Firebase UserRecord by email
     */
    public Mono<UserRecord> getUserRecord(String email) {
        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(
                        FirebaseAuth.getInstance().getUserByEmailAsync(email)))
                .onErrorResume(e -> Mono.error(new AuthenticationException("User not found: " + email)));
    }

    /**
     * Signs in with Firebase REST API
     */
    public Mono<Void> signInWithFirebase(String email, String password) {
        String firebaseAuthUrl = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="
                + firebaseConfig.getFirebaseApiKey();

        return webClient.post()
                .uri(firebaseAuthUrl)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .bodyValue(Map.of(
                        "email", email,
                        "password", password,
                        "returnSecureToken", true
                ))
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, response ->
                        response.bodyToMono(Map.class).flatMap(errorBody -> {
                            logger.warn("🔐 Firebase auth error for {}: {}", email, errorBody);
                            String errorCode = extractFirebaseRestErrorCode(errorBody);
                            return Mono.error(new FirebaseRestAuthException(errorCode, "Firebase auth failed"));
                        }))
                .bodyToMono(Map.class)
                .doOnSuccess(response -> {
                    if (response != null && response.containsKey("idToken")) {
                        logger.info("🔓 Authenticated: {} (UID: {})", email, response.get("localId"));
                    }
                })
                .then();
    }

    // ============================================================================
    // ERROR HANDLING & TRANSLATION
    // ============================================================================

    /**
     * Translates Firebase exceptions to application-specific exceptions
     */
    public Throwable translateFirebaseException(Throwable e) {
        Throwable actual = e.getCause() != null ? e.getCause() : e;

        if (actual instanceof FirebaseAuthException authEx) {
            return translateFirebaseAuthException(authEx);
        }

        if (actual instanceof FirebaseRestAuthException restEx) {
            return translateFirebaseRestException(restEx);
        }

        if (actual instanceof BadCredentialsException) {
            return AuthException.invalidCredentials();
        }

        if (actual instanceof DisabledException) {
            return AuthException.accountDisabled();
        }

        logger.error("Unhandled auth exception: {} - {}",
                actual.getClass().getSimpleName(), actual.getMessage());
        return new AuthException("Unexpected error during authentication",
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private Throwable translateFirebaseAuthException(FirebaseAuthException authEx) {
        String errorCode = String.valueOf(authEx.getErrorCode());
        return switch (errorCode) {
            case "USER_NOT_FOUND", "NOT_FOUND", "user-not-found",
                 "invalid-email", "EMAIL_NOT_FOUND", "INVALID_EMAIL" ->
                    AuthException.accountNotFound();
            case "WRONG_PASSWORD", "wrong-password", "INVALID_PASSWORD" ->
                    AuthException.invalidCredentials();
            case "USER_DISABLED", "user-disabled" ->
                    AuthException.accountDisabled();
            case "TOO_MANY_ATTEMPTS_TRY_LATER", "too-many-requests" ->
                    AuthException.rateLimitExceeded();
            case "EMAIL_NOT_VERIFIED" ->
                    AuthException.emailNotVerified();
            default -> new AuthException("Authentication failed: " + errorCode,
                    HttpStatus.UNAUTHORIZED);
        };
    }

    private Throwable translateFirebaseRestException(FirebaseRestAuthException restEx) {
        String errorCode = restEx.getErrorCode();
        return switch (errorCode) {
            case "EMAIL_NOT_FOUND", "INVALID_EMAIL" -> AuthException.accountNotFound();
            case "INVALID_PASSWORD" -> AuthException.invalidCredentials();
            case "USER_DISABLED" -> AuthException.accountDisabled();
            case "TOO_MANY_ATTEMPTS_TRY_LATER" -> AuthException.rateLimitExceeded();
            default -> new AuthException("Authentication failed: " + errorCode,
                    HttpStatus.UNAUTHORIZED);
        };
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private String extractFirebaseRestErrorCode(Map<?, ?> errorBody) {
        try {
            Map<?, ?> error = (Map<?, ?>) errorBody.get("error");
            return (String) ((Map<?, ?>) ((List<?>) error.get("errors")).get(0)).get("message");
        } catch (Exception e) {
            logger.error("⚠️ Failed to extract Firebase error code: {}", e.getMessage());
            return "unknown";
        }
    }
}