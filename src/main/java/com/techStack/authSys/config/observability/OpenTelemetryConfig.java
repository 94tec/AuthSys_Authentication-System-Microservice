package com.techStack.authSys.config.observability;

import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenTelemetryConfig {

    @Bean
    public Tracer tracer() {
        return GlobalOpenTelemetry.getTracer("authSys-tracer");
    }
}

