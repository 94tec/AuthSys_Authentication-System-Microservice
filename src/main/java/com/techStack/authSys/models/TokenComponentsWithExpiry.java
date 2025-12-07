package com.techStack.authSys.models;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Builder
@Getter
public class TokenComponentsWithExpiry {
    private final TokenPair tokenPair;
    private final String userId;
    private final String ipAddress;
    private final String userAgent;
    private final Instant accessTokenExpiry;
    private final Instant refreshTokenExpiry;

    public TokenComponentsWithExpiry(TokenPair tokenPair, String userId, String ipAddress, String userAgent,
                                     Instant accessTokenExpiry, Instant refreshTokenExpiry) {
        this.tokenPair = tokenPair;
        this.userId = userId;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.accessTokenExpiry = accessTokenExpiry;
        this.refreshTokenExpiry = refreshTokenExpiry;
    }

    // Convenience getter to get refresh token from tokenPair
    public String getRefreshToken() {
        return tokenPair != null ? tokenPair.getRefreshToken() : null;
    }

    // Convenience getter to get access token from tokenPair
    public String getAccessToken() {
        return tokenPair != null ? tokenPair.getAccessToken() : null;
    }
}