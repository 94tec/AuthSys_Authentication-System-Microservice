package com.techStack.authSys.notification.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Notification configuration — email via Brevo only.
 *
 * application.yml:
 * ---
 * notification:
 *   brevo:
 *     enabled:       ${BREVO_ENABLED:true}   # false = log emails instead of sending (local dev)
 *     api-key:       ${BREVO_API_KEY}
 *     sender-email:  noreply@damuchisafaris.co.ke   # must be a verified sender/domain in Brevo
 *     sender-name:   Damuchi Safaris
 *   retry:
 *     max-attempts:  3
 *     window-hours:  24
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "notification")
public class NotificationConfig {

    private Brevo brevo = new Brevo();
    private Retry retry = new Retry();

    @Getter @Setter
    public static class Brevo {
        private boolean enabled = true;
        private String apiKey;
        private String senderEmail = "noreply@damuchisafaris.co.ke";
        private String senderName  = "Damuchi Safaris";
        /** Brevo transactional email API endpoint */
        private String apiUrl      = "https://api.brevo.com/v3/smtp/email";
    }

    @Getter @Setter
    public static class Retry {
        /** Maximum send attempts before marking FAILED permanently */
        private int maxAttempts = 3;
        /** Only retry notifications created within this many hours */
        private int windowHours = 24;
    }
}