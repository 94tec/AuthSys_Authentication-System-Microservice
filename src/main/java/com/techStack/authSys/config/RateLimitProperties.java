package com.techStack.authSys.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "security.rate-limit")
public class RateLimitProperties {
    private int global;
    private int ipStandard;
    private int ipSensitive;
    private int windowMinutes;
}

