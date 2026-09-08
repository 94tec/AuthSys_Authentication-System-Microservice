package com.techStack.authSys.notification.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Notification channel configuration.
 * All values injected from environment variables.
 *
 * application.yml:
 * ---
 * notification:
 *   brevo:
 *     api-key:       ${BREVO_API_KEY}
 *     sender-email:  noreply@damuchisafaris.co.ke
 *     sender-name:   Damuchi Safaris
 *   africastalking:
 *     api-key:       ${AT_API_KEY}
 *     username:      ${AT_USERNAME}         # "sandbox" for testing
 *     sender-id:     ${AT_SENDER_ID}        # e.g. "DAMUCHI" (approved short-code)
 *     whatsapp-from: ${AT_WHATSAPP_FROM}    # WhatsApp number from AT console
 *   retry:
 *     max-attempts:  3
 *     window-hours:  24                     # only retry within 24h of creation
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "notification")
public class NotificationConfig {

    private Brevo            brevo            = new Brevo();
    private AfricasTalking   africasTalking   = new AfricasTalking();
    private Retry            retry            = new Retry();

    @Getter @Setter
    public static class Brevo {
        private String apiKey;
        private String senderEmail = "noreply@damuchisafaris.co.ke";
        private String senderName  = "Damuchi Safaris";
        /** Brevo transactional email API endpoint */
        private String apiUrl      = "https://api.brevo.com/v3/smtp/email";
    }

    @Getter @Setter
    public static class AfricasTalking {
        private String apiKey;
        private String username;
        private String senderId;
        private String whatsappFrom;
        /** "sandbox" or "production" */
        private String environment = "sandbox";

        public String getSmsUrl() {
            return "sandbox".equalsIgnoreCase(environment)
                ? "https://api.sandbox.africastalking.com/version1/messaging"
                : "https://api.africastalking.com/version1/messaging";
        }

        public String getWhatsAppUrl() {
            return "sandbox".equalsIgnoreCase(environment)
                ? "https://chat.sandbox.africastalking.com/whatsapp/send"
                : "https://chat.africastalking.com/whatsapp/send";
        }

        public boolean isProduction() {
            return "production".equalsIgnoreCase(environment);
        }
    }

    @Getter @Setter
    public static class Retry {
        /** Maximum send attempts before marking FAILED permanently */
        private int maxAttempts  = 3;
        /** Only retry notifications created within this many hours */
        private int windowHours  = 24;
    }
}
