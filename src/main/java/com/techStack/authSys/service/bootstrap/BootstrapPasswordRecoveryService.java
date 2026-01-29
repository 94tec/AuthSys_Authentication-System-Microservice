package com.techStack.authSys.service.bootstrap;

import com.google.firebase.auth.FirebaseAuth;
import com.techStack.authSys.service.notification.EmailServiceInstance1;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * SECURE password recovery using Firebase's built-in password reset.
 * NO password storage - uses Firebase Authentication's native functionality.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BootstrapPasswordRecoveryService {

    private final EmailServiceInstance1 emailService;

    /**
     * Sends Firebase password reset link to user.
     * SECURE: Uses Firebase's native password reset, no password storage.
     */
    public Mono<Void> sendPasswordResetLink(String email) {
        return Mono.fromCallable(() -> {
            log.info("🔄 Sending Firebase password reset link to: {}", HelperUtils.maskEmail(email));

            try {
                // Generate Firebase password reset link
                String resetLink = FirebaseAuth.getInstance()
                        .generatePasswordResetLink(email);

                // Send via email
                String subject = "Reset Your Super Admin Password";
                String body = String.format("""
                        Hello,
                        
                        A password reset was requested for your Super Admin account.
                        
                        Click the link below to reset your password:
                        %s
                        
                        This link expires in 1 hour.
                        
                        If you didn't request this, please ignore this email.
                        
                        Best regards,
                        Security Team
                        """, resetLink);

                emailService.sendEmail(email, subject, body).block();

                log.info("✅ Password reset link sent successfully");
                return null;
            } catch (Exception e) {
                log.error("❌ Failed to send password reset link: {}", e.getMessage());
                throw new RuntimeException("Failed to send password reset link", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    /**
     * Alternative: Send manual instructions to use Firebase Console.
     */
    public Mono<Void> sendManualResetInstructions(String email) {
        String subject = "Super Admin Account - Password Reset Instructions";
        String body = String.format("""
                Hello,
                
                Your Super Admin account was created, but the welcome email could not be delivered.
                
                To access your account, please follow these steps:
                
                1. Go to Firebase Console: https://console.firebase.google.com
                2. Select your project
                3. Go to Authentication > Users
                4. Find your account: %s
                5. Click "Reset Password"
                6. Check your email for the reset link
                
                Or contact your system administrator for assistance.
                
                Best regards,
                Security Team
                """, email);

        return emailService.sendEmail(email, subject, body)
                .doOnSuccess(v -> log.info("✅ Manual reset instructions sent"))
                .doOnError(e -> log.error("❌ Failed to send instructions: {}", e.getMessage()));
    }
}