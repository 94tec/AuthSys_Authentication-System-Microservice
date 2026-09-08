package com.techStack.authSys.payment.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * M-Pesa Daraja API configuration.
 *
 * Bound from application.yml under the prefix "mpesa".
 * All values injected from environment variables — no secrets in source.
 *
 * application.yml:
 * ---
 * mpesa:
 *   consumer-key:    ${MPESA_CONSUMER_KEY}
 *   consumer-secret: ${MPESA_CONSUMER_SECRET}
 *   shortcode:       ${MPESA_SHORTCODE}
 *   passkey:         ${MPESA_PASSKEY}
 *   callback-url:    ${MPESA_CALLBACK_URL}
 *   environment:     sandbox   # → production when going live
 *
 * Environments:
 *   sandbox    → https://sandbox.safaricom.co.ke
 *   production → https://api.safaricom.co.ke
 *
 * Daraja console: https://developer.safaricom.co.ke
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "mpesa")
public class MpesaConfig {

    /** App consumer key from Daraja portal */
    private String consumerKey;

    /** App consumer secret from Daraja portal */
    private String consumerSecret;

    /**
     * Business shortcode (Paybill or Till number).
     * For sandbox use: 174379
     */
    private String shortcode;

    /**
     * Lipa Na M-Pesa Online passkey from Daraja portal.
     * Used to generate the Base64 password for STK push requests.
     */
    private String passkey;

    /**
     * Your publicly accessible callback URL.
     * Safaricom will POST the payment result here.
     * Must be HTTPS — localhost will not work.
     * e.g. https://api.damuchisafaris.co.ke/api/payments/mpesa/callback
     */
    private String callbackUrl;

    /**
     * "sandbox" or "production"
     */
    private String environment = "sandbox";

    /**
     * Transaction type for STK push.
     * "CustomerPayBillOnline" for Paybill.
     * "CustomerBuyGoodsOnline" for Till.
     */
    private String transactionType = "CustomerPayBillOnline";

    // ── Derived helpers ───────────────────────────────────────────────────────

    public String getBaseUrl() {
        return "sandbox".equalsIgnoreCase(environment)
            ? "https://sandbox.safaricom.co.ke"
            : "https://api.safaricom.co.ke";
    }

    public String getAuthUrl() {
        return getBaseUrl() + "/oauth/v1/generate?grant_type=client_credentials";
    }

    public String getStkPushUrl() {
        return getBaseUrl() + "/mpesa/stkpush/v1/processrequest";
    }

    public String getStkQueryUrl() {
        return getBaseUrl() + "/mpesa/stkpushquery/v1/query";
    }

    public boolean isProduction() {
        return "production".equalsIgnoreCase(environment);
    }
}
