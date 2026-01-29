package com.techStack.authSys.service.verification;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.FieldValue;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.WriteResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.exception.account.UserNotFoundException;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.auth.TokenClaims;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Handles email verification and resend operations.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private static final String COLLECTION_USERS = "users";

    private final JwtService jwtService;
    private final FirebaseAuth firebaseAuth;
    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final EmailVerificationOrchestrator emailOrchestrator;

    /**
     * Verifies email using verification token.
     * Enforces IP address validation for security.
     */
    public Mono<Void> verifyEmail(String token, String ipAddress) {
        return jwtService.verifyEmailVerificationToken(token)
                .flatMap(claims ->
                        validateIpAddress(claims, ipAddress)
                                .then(updateUserVerificationStatus(claims.userId()))
                                .then(logSuccessfulVerification(claims, ipAddress))
                )
                .doOnSuccess(__ -> log.info("✅ Email verification completed successfully"))
                .doOnError(e -> logVerificationError(e, ipAddress));
    }

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
        }).onErrorResume(e -> {
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
        });
    }

    /**
     * Validates that verification is attempted from the same IP as registration.
     * SECURITY: Prevents token hijacking from different locations.
     */
    private Mono<Void> validateIpAddress(TokenClaims claims, String ipAddress) {
        if (!claims.ipAddress().equals(ipAddress)) {
            return logFailedAttempt(claims, ipAddress)
                    .then(Mono.error(new CustomException(
                            HttpStatus.FORBIDDEN,
                            "Email verification must be completed from the registration IP address"
                    )));
        }
        return Mono.empty();
    }

    /**
     * Updates verification status in both Firebase Auth and Firestore.
     */
    private Mono<Void> updateUserVerificationStatus(String userId) {
        return updateFirebaseUser(userId)
                .then(updateFirestoreUser(userId));
    }

    /**
     * Marks user as verified in Firebase Auth.
     */
    private Mono<Void> updateFirebaseUser(String userId) {
        return Mono.fromCallable(() -> {
            firebaseAuth.updateUser(
                    new UserRecord.UpdateRequest(userId)
                            .setEmailVerified(true)
            );
            return null;
        });
    }

    /**
     * Updates verification status in Firestore and enables the account.
     */
    private Mono<Void> updateFirestoreUser(String userId) {
        ApiFuture<WriteResult> future = firestore.collection(COLLECTION_USERS)
                .document(userId)
                .update(
                        "emailVerified", true,
                        "enabled", true,
                        "verificationToken", FieldValue.delete()
                );

        return Mono.fromFuture(() -> FirestoreUtil.toCompletableFuture(future))
                .then();
    }

    /**
     * Logs successful email verification for audit trail.
     */
    private Mono<Void> logSuccessfulVerification(TokenClaims claims, String ipAddress) {
        return Mono.fromRunnable(() -> auditLogService.logAudit(
                buildUser(claims),
                ActionType.EMAIL_VERIFICATION,
                "Email verified successfully",
                ipAddress
        ));
    }

    /**
     * Logs failed verification attempt (wrong IP).
     */
    private Mono<Void> logFailedAttempt(TokenClaims claims, String ipAddress) {
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
     * Logs verification errors for monitoring.
     */
    private void logVerificationError(Throwable e, String ipAddress) {
        if (e instanceof CustomException) {
            CustomException ce = (CustomException) e;
            log.warn("Email verification failed for IP {}: {} {}",
                    ipAddress, ce.getStatus().value(), ce.getMessage());
        } else {
            log.error("Email verification failed for IP {}: {}",
                    ipAddress, e.getMessage(), e);
        }
    }

    /**
     * Builds a minimal User object from token claims.
     */
    private User buildUser(TokenClaims claims) {
        return User.builder()
                .id(claims.userId())
                .email(claims.email())
                .build();
    }
}
