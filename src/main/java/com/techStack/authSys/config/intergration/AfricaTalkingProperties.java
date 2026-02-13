package com.techStack.authSys.config.intergration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "sms.africastalking")
public class AfricaTalkingProperties {

    /**
     * Enable/disable sending real SMS
     */
    private boolean enabled = false;

    /**
     * sandbox or production
     */
    private String environment = "sandbox";

    /**
     * Africa's Talking username (sandbox or your live username)
     */
    private String username = "sandbox";

    /**
     * Africa's Talking API Key
     */
    private String apiKey;

    /**
     * Optional sender ID/shortcode
     */
    private String from;

    /**
     * Endpoint
     */
    private String smsUrl = "https://api.africastalking.com/version1/messaging";

    /**
     * Dev: log OTP when disabled
     */
    private boolean logOtpWhenDisabled = true;

    public boolean isProduction() {
        return "production".equalsIgnoreCase(environment);
    }

    public String senderOrNull() {
        return (from == null || from.isBlank()) ? null : from;
    }
}
