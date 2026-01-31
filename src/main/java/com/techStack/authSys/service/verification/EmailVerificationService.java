package com.techStack.authSys.service.verification;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.FieldValue;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.auth.TokenClaims;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;

import static com.techStack.authSys.constants.SecurityConstants.COLLECTION_USERS;

/**
 * Email Verification Service
 *
 * Handles email verification and resend operations.
 * Uses Clock for all timestamp operations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    /* =========================
       Dependencies
       ========================= */

    private final JwtService jwtService;
    private final FirebaseAuth firebaseAuth;
    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final EmailVerificationOrchestrator emailOrchestrator;
    private final Clock clock;

    /* =========================
       Email Verification
       ========================= */

    /**
     * Verify email using verification token.
     * Enforces IP address validation for security.
     */
    public Mono<Void> verifyEmail(String token, String ipAddress) {
        Instant now = clock.instant();

        return jwtService.verifyEmailVerificationToken(token)
                .flatMap(claims ->
                        validateIpAddress(claims, ipAddress)
                                .then(updateUserVerificationStatus(claims.userId(), now))
                                .then(logSuccessfulVerification(claims, ipAddress, now))
                )
                .doOnSuccess(__ -> log.info("✅ Email verification completed successfully"))
                .doOnError(e -> logVerificationError(e, ipAddress));
    }

    /**
     * Resend verification email to user
     */
    public Mono<Void> resendVerificationEmail(String email, String ipAddress) {
        return Mono.zip(
                // Get verification status from Firebase Auth
                Mono.fromCallable(() -> FirebaseAuth.getInstance().getUserByEmail(email))
                        .subscribeOn(Schedulers.boundedElastic())
                        .map(UserRecord::isEmailVerified),

                // Get user details from Firestore
                firebaseServiceAuth.findByEmail(email)
        ).flatMap(tuple -> {
            boolean isVerified = tuple.getT1();
            User user = tuple.getT2();

            if (isVerified) {
                return Mono.error(new CustomException(
                        HttpStatus.BAD_REQUEST,
                        "Email is already verified"
                ));
            }

            return emailOrchestrator.sendVerificationEmailSafely(user, ipAddress)
                    .then();

        }).onErrorResume(e -> handleResendError(e));
    }

    /* =========================
       Validation Methods
       ========================= */

    /**
     * Validate that verification is attempted from same IP as registration.
     * SECURITY: Prevents token hijacking from different locations.
     */
    private Mono<Void> validateIpAddress(TokenClaims claims, String ipAddress) {
        if (!claims.ipAddress().equals(ipAddress)) {
            return logFailedAttempt(claims, ipAddress, clock.instant())
                    .then(Mono.error(new CustomException(
                            HttpStatus.FORBIDDEN,
                            "Email verification must be completed from the registration IP address"
                    )));
        }
        return Mono.empty();
    }

    /* =========================
       Update Operations
       ========================= */

    /**
     * Update verification status in both Firebase Auth and Firestore
     */
    private Mono<Void> updateUserVerificationStatus(String userId, Instant now) {
        return updateFirebaseUser(userId)
                .then(updateFirestoreUser(userId, now));
    }

    /**
     * Mark user as verified in Firebase Auth
     */
    private Mono<Void> updateFirebaseUser(String userId) {
        return Mono.fromCallable(() -> {
            firebaseAuth.updateUser(
                    new UserRecord.UpdateRequest(userId)
                            .setEmailVerified(true)
            );
            return null;
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Update verification status in Firestore and enable account
     */
    private Mono<Void> updateFirestoreUser(String userId, Instant now) {
        ApiFuture<WriteResult> future = firestore.collection(COLLECTION_USERS)
                .document(userId)
                .update(
                        "emailVerified", true,
                        "enabled", true,
                        "verificationToken", FieldValue.delete(),
                        "updatedAt", now
                );

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .then();
    }

    /* =========================
       Audit Logging
       ========================= */

    /**
     * Log successful email verification
     */
    private Mono<Void> logSuccessfulVerification(
            TokenClaims claims,
            String ipAddress,
            Instant now
    ) {
        return Mono.fromRunnable(() -> auditLogService.logAudit(
                buildUser(claims),
                ActionType.EMAIL_VERIFICATION,
                "Email verified successfully",
                ipAddress
        ));
    }

    /**
     * Log failed verification attempt (wrong IP)
     */
    private Mono<Void> logFailedAttempt(
            TokenClaims claims,
            String ipAddress,
            Instant now
    ) {
        return Mono.fromRunnable(() -> {
            log.warn("⚠️ Email verification attempted from different IP. " +
                    "Expected: {}, Got: {}", claims.ipAddress(), ipAddress);

            auditLogService.logAudit(
                    buildUser(claims),
                    ActionType.EMAIL_VERIFICATION,
                    "Attempt to verify email from different IP",
                    ipAddress
            );
        });
    }

    /**
     * Log verification errors for monitoring
     */
    private void logVerificationError(Throwable e, String ipAddress) {
        if (e instanceof CustomException ce) {
            log.warn("Email verification failed for IP {}: {} {}",
                    ipAddress, ce.getStatus().value(), ce.getMessage());
        } else {
            log.error("Email verification failed for IP {}: {}",
                    ipAddress, e.getMessage(), e);
        }
    }

    /* =========================
       Error Handling
       ========================= */

    /**
     * Handle resend verification errors
     */
    private Mono<Void> handleResendError(Throwable e) {
        if (e instanceof FirebaseAuthException) {
            return Mono.error(new CustomException(
                    HttpStatus.NOT_FOUND,
                    "User not found in authentication system"
            ));
        }
        if (e instanceof UserNotFoundException) {
            return Mono.error(new CustomException(
                    HttpStatus.NOT_FOUND,
                    "User not found in database"
            ));
        }
        return Mono.error(new CustomException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to resend verification email"
        ));
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Build minimal User object from token claims
     */
    private User buildUser(TokenClaims claims) {
        return User.builder()
                .id(claims.userId())
                .email(claims.email())
                .build();
    }
}