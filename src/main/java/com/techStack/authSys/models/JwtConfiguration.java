package com.techStack.authSys.models;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtConfiguration {
    private String secret;
    private long accessTokenExpiration;
    private long refreshTokenExpiration;
    private long clockSkew;
}
