package com.techStack.authSys.config.security;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * JWT Configuration
 *
 * Binds JWT-related properties from application.yaml under the "jwt" prefix.
 * All secret keys are validated at startup — a missing or undersized key is
 * a hard startup failure, not a runtime NPE.
 *
 * Property naming fix:
 *   accessTokenExpiration is stored in SECONDS.
 *   The original getAccessTokenExpirationInMillis() returned the raw
 *   accessTokenExpiration value without converting — so it was returning
 *   seconds while claiming to return millis. Fixed to multiply by 1000.
 *
 * Prefix alignment:
 *   @ConfigurationProperties(prefix = "jwt") — unchanged.
 *   Your application.yaml must have a "jwt:" block at root level (not "app.jwt:").
 *   This is separate from PermissionsYamlConfig which uses "app:" prefix.
 */
@Validated
@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtConfig {

    // -------------------------------------------------------------------------
    // Secret key properties
    // -------------------------------------------------------------------------

    /** Base key for general signing. Must be Base64-encoded or plain UTF-8, min 512 bits. */
    @NotBlank(message = "jwt.secret must not be blank")
    private String secret;

    /** Pepper mixed into the email verification key. Must be non-blank. */
    @NotBlank(message = "jwt.pepper must not be blank")
    private String pepper;

    /** Secret for access token signing. Must be Base64-encoded or plain UTF-8, min 512 bits. */
    @NotBlank(message = "jwt.access must not be blank")
    private String access;

    /** Secret for refresh token signing. Must be Base64-encoded or plain UTF-8, min 512 bits. */
    @NotBlank(message = "jwt.refresh must not be blank")
    private String refresh;

    // -------------------------------------------------------------------------
    // Expiration properties (all stored in SECONDS unless noted)
    // -------------------------------------------------------------------------

    /** General token expiration in milliseconds. Default: 1 hour. */
    @Positive(message = "jwt.expiration-ms must be positive")
    private long expirationMs = 3_600_000L;

    /**
     * Access token expiration in SECONDS. Default: 3600 (1 hour).
     * Used by getAccessTokenExpirationInSeconds() and getAccessTokenExpirationInMillis().
     */
    @Positive(message = "jwt.access-token-expiration must be positive")
    private long accessTokenExpiration = 3_600L;

    /**
     * Refresh token expiration in MILLISECONDS. Default: 30 days.
     * Divided by 1000 in getRefreshTokenExpirationInSeconds().
     */
    @Positive(message = "jwt.refresh-expiration-ms must be positive")
    private long refreshExpirationMs = 2_592_000_000L;

    /**
     * Email verification token expiration in SECONDS. Default: 1800 (30 minutes).
     */
    @Positive(message = "jwt.email-verification-expiration must be positive")
    private long emailVerificationExpiration = 1_800L;

    /** Allowed clock skew in seconds for JWT validation. Default: 30 seconds. */
    @Positive(message = "jwt.clock-skew-seconds must be positive")
    private long clockSkewSeconds = 30L;

    /** JWT issuer claim value. */
    private String issuer = "techStack-auth";

    // -------------------------------------------------------------------------
    // Secret key beans
    // -------------------------------------------------------------------------

    @Bean
    public SecretKey secretKey() {
        return validateAndCreateKey(secret, "jwt.secret");
    }

    @Bean
    public SecretKey accessTokenSecretKey() {
        return validateAndCreateKey(access, "jwt.access");
    }

    @Bean
    public SecretKey refreshTokenSecretKey() {
        return validateAndCreateKey(refresh, "jwt.refresh");
    }

    @Bean
    public SecretKey emailVerificationSecretKey() {
        return validateAndCreateKey(secret + pepper, "jwt.secret+jwt.pepper");
    }

    // -------------------------------------------------------------------------
    // Parser beans
    // -------------------------------------------------------------------------

    @Bean
    public JwtParser jwtParser() {
        return Jwts.parserBuilder()
                .setSigningKey(accessTokenSecretKey())
                .setAllowedClockSkewSeconds(clockSkewSeconds)
                .build();
    }

    @Bean
    public JwtParser refreshTokenJwtParser() {
        return Jwts.parserBuilder()
                .setSigningKey(refreshTokenSecretKey())
                .setAllowedClockSkewSeconds(clockSkewSeconds)
                .build();
    }

    @Bean
    public JwtParser emailVerificationJwtParser() {
        return Jwts.parserBuilder()
                .setSigningKey(emailVerificationSecretKey())
                .setAllowedClockSkewSeconds(clockSkewSeconds)
                .build();
    }

    // -------------------------------------------------------------------------
    // Builder beans
    // -------------------------------------------------------------------------

    @Bean
    public JwtBuilder jwtBuilder() {
        return Jwts.builder()
                .signWith(accessTokenSecretKey(), SignatureAlgorithm.HS512);
    }

    @Bean
    public JwtBuilder refreshTokenJwtBuilder() {
        return Jwts.builder()
                .signWith(refreshTokenSecretKey(), SignatureAlgorithm.HS512);
    }

    @Bean
    public JwtBuilder emailVerificationJwtBuilder() {
        return Jwts.builder()
                .signWith(emailVerificationSecretKey(), SignatureAlgorithm.HS512);
    }

    // -------------------------------------------------------------------------
    // Expiration accessors
    // -------------------------------------------------------------------------

    /**
     * Access token expiration in seconds.
     * e.g. used by JwtService to set the exp claim: issuedAt.plusSeconds(...)
     */
    public long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration;
    }

    /**
     * Access token expiration in milliseconds.
     *
     * Fix from original: the original returned accessTokenExpiration directly,
     * which is stored in SECONDS. Multiplied by 1000 to produce the correct
     * millis value. e.g. 3600 seconds → 3_600_000 ms.
     */
    public long getAccessTokenExpirationInMillis() {
        return accessTokenExpiration * 1_000L;
    }

    /**
     * Refresh token expiration in seconds.
     * Converts from the stored milliseconds value.
     */
    public long getRefreshTokenExpirationInSeconds() {
        return refreshExpirationMs / 1_000L;
    }

    /**
     * Email verification token expiration in seconds.
     */
    public long getEmailVerificationExpirationInSeconds() {
        return emailVerificationExpiration;
    }

    // -------------------------------------------------------------------------
    // Key validation
    // -------------------------------------------------------------------------

    /**
     * Validates a key string and creates a SecretKey for HS512 signing.
     *
     * Tries Base64 decoding first (preferred for production keys).
     * Falls back to raw UTF-8 bytes (acceptable for dev/test keys).
     * Enforces a minimum of 512 bits (64 bytes) required by HS512.
     *
     * @param keyString    the raw key string from properties
     * @param propertyName used in the error message if validation fails
     * @return validated SecretKey
     * @throws IllegalArgumentException if key is null, blank, or under 512 bits
     */
    private SecretKey validateAndCreateKey(String keyString, String propertyName) {
        if (keyString == null || keyString.isBlank()) {
            throw new IllegalArgumentException(
                    propertyName + " must not be null or empty");
        }

        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(keyString);
        } catch (IllegalArgumentException e) {
            // Not Base64 — treat as raw UTF-8
            keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
        }

        if (keyBytes.length < 64) {
            throw new IllegalArgumentException(String.format(
                    "%s must be at least 512 bits (64 bytes) for HS512. " +
                            "Current size: %d bits (%d bytes). " +
                            "Generate a suitable key with: openssl rand -base64 64",
                    propertyName, keyBytes.length * 8, keyBytes.length));
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }
}