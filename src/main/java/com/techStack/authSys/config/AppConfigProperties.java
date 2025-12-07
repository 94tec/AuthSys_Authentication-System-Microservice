package com.techStack.authSys.config;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app")
@Primary
public class AppConfigProperties {
    private String superAdminEmail;
    private String superAdminPhone;
}

