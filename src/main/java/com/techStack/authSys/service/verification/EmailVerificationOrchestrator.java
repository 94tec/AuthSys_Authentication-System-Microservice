package com.techStack.authSys.service.verification;

import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.Firestore;
import com.techStack.authSys.config.core.AppConfig;
import com.techStack.authSys.models.audit.ActionType;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.notification.EmailService;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.EncryptionService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;

import static com.techStack.authSys.constants.SecurityConstants.*;

/**
 * Email Verification Orchestrator
 *
 * Orchestrates email verification workflows.
 * Handles token generation, email sending, and token storage.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationOrchestrator {

    /* =========================
       Dependencies
       ========================= */

    private final JwtService jwtService;
    private final EmailService emailService;
    private final EncryptionService encryptionService;
    private final AuditLogService auditLogService;
    private final Firestore firestore;
    private final AppConfig appConfig;
    private final Clock clock;

    /* =========================
       Verification Email
       ========================= */

    /**
     * Send verification email with graceful error handling.
     * Registration continues even if email fails.
     */
    public Mono<User> sendVerificationEmailSafely(User user, String ipAddress) {
        return sendVerificationEmail(user, ipAddress)
                .onErrorResume(e -> {
                    log.warn("Verification email failed for {}: {}",
                            user.getEmail(), e.getMessage());
                    log.debug("Full error details:", e);

                    auditLogService.logAudit(
                            user,
                            ActionType.EMAIL_FAILURE,
                            "Verification email failed: " + e.getMessage(),
                            ipAddress
                    );

                    // Don't block registration - user can resend later
                    return Mono.just(user);
                })
                .doOnSuccess(u -> log.info("Verification email process completed for: {}",
                        u.getEmail()));
    }

    /**
     * Generate token, send email, and store hashed token
     */
    private Mono<User> sendVerificationEmail(User user, String ipAddress) {
        Instant now = clock.instant();

        return jwtService.generateEmailVerificationToken(
                        user.getId(),
                        user.getEmail(),
                        ipAddress
                )
                .flatMap(token -> {
                    String hashedToken = encryptionService.hashToken(token);
                    String verificationLink = buildVerificationLink(token);

                    // Send email and store token in parallel
                    Mono<Void> emailMono = sendEmail(user.getEmail(), verificationLink);
                    Mono<Void> storeMono = storeVerificationToken(user.getId(), hashedToken, now);

                    return emailMono
                            .then(storeMono)
                            .thenReturn(user);
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    /* =========================
       Email Operations
       ========================= */

    /**
     * Send verification email to user
     */
    private Mono<Void> sendEmail(String email, String verificationLink) {
        return emailService.sendVerificationEmail(email, verificationLink)
                .doOnSuccess(__ -> log.info("✅ Sent verification email to {}", email))
                .doOnError(e -> log.error("❌ Failed to send email to {}: {}",
                        email, e.getMessage()));
    }

    /* =========================
       Token Storage
       ========================= */

    /**
     * Store hashed verification token in Firestore
     */
    private Mono<Void> storeVerificationToken(
            String userId,
            String hashedToken,
            Instant now
    ) {
        Instant expiresAt = now.plus(TOKEN_EXPIRY);

        Map<String, Object> updateData = Map.of(
                FIELD_VERIFICATION_TOKEN_HASH, hashedToken,
                FIELD_TOKEN_EXPIRES_AT, expiresAt,
                "updatedAt", now
        );

        DocumentReference userDoc = firestore.collection(COLLECTION_USERS).document(userId);

        return Mono.fromFuture(() ->
                        FirestoreUtil.toCompletableFuture(userDoc.update(updateData))
                )
                .doOnSuccess(__ -> log.info("✅ Stored verification token for user: {} (expires: {})",
                        userId, expiresAt))
                .doOnError(e -> log.error("❌ Failed to store token for user: {}", userId, e))
                .then();
    }

    /* =========================
       Utility Methods
       ========================= */

    /**
     * Build verification link with token
     */
    private String buildVerificationLink(String token) {
        return String.format("%s/api/v1/auth/verify-email?token=%s",
                appConfig.getBaseUrl(), token);
    }
}