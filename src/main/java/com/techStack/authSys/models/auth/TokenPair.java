package com.techStack.authSys.models.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Token Pair Model
 *
 * Contains access token and refresh token.
 */
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenPair {

        @JsonProperty("accessToken")
        private String accessToken;

        @JsonProperty("refreshToken")
        private String refreshToken;
}