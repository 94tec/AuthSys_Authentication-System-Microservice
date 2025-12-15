package com.techStack.authSys.config;

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

@Validated
@Configuration
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtConfig {
    // Secret keys configuration
    @NotBlank(message = "jwt.secret must not be blank")
    private String secret;

    @NotBlank(message = "jwt.pepper must not be blank")
    private String pepper;

    @NotBlank(message = "jwt.access must not be blank")
    private String access;

    @NotBlank(message = "jwt.refresh must not be blank")
    private String refresh;

    // Expiration times
    @Positive(message = "jwt.expiration.ms must be positive")
    private long expirationMs = 3600000; // Default: 1 hour

    @Positive(message = "jwt.access-token.expiration must be positive")
    private long accessTokenExpiration = 3600; // Default: 1 hour (in seconds)

    @Positive(message = "jwt.refresh.expiration.ms must be positive")
    private long refreshExpirationMs = 2592000000L; // Default: 30 days

    @Positive(message = "jwt.email-verification.expiration must be positive")
    private long emailVerificationExpiration = 1800; // Default: 30 minutes (in seconds)

    @Positive(message = "jwt.clock.skew.seconds must be positive")
    private long clockSkewSeconds = 30; // Default: 1 minute

    private String issuer = "techStack-auth"; // Default value

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
        String combinedKey = secret + pepper;
        return validateAndCreateKey(combinedKey, "jwt.secret+jwt.pepper");
    }

    private SecretKey validateAndCreateKey(String keyString, String propertyName) {
        if (keyString == null || keyString.isBlank()) {
            throw new IllegalArgumentException(propertyName + " must not be null or empty");
        }

        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(keyString);
        } catch (IllegalArgumentException e) {
            keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
        }

        if (keyBytes.length < 64) {
            throw new IllegalArgumentException(
                    String.format("%s must be at least 512 bits (64 bytes). Current size: %d bits",
                            propertyName, keyBytes.length * 8));
        }

        return Keys.hmacShaKeyFor(keyBytes);
    }

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

    // Helper methods
    public long getAccessTokenExpirationInSeconds() {
        return accessTokenExpiration;
    }

    public long getAccessTokenExpirationInMillis() {
        return accessTokenExpiration;
    }

    public long getRefreshTokenExpirationInSeconds() {
        return refreshExpirationMs / 1000;
    }

    public long getEmailVerificationExpirationInSeconds() {
        return emailVerificationExpiration;
    }
}