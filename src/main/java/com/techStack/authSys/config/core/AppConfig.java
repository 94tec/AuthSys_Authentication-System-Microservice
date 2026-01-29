package com.techStack.authSys.config.core;


import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
public class AppConfig {

    @Value("${app.base-url}")
    private String baseUrl;
}

