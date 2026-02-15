package com.techStack.authSys.config.core;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "auth.login-otp")
public class LoginOtpProperties {
    private boolean enabled = true;
}
