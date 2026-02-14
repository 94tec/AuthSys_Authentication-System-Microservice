package com.techStack.authSys.config.core;



import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Tracer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenTelemetryConfig {

    @Bean
    public OpenTelemetry openTelemetry() {
        // Use OpenTelemetry.noop() which is available in the API
        return OpenTelemetry.noop();
    }

    @Bean
    public Tracer tracer(OpenTelemetry openTelemetry) {
        // Get tracer from OpenTelemetry (will be no-op)
        return openTelemetry.getTracer("com.techStack.authSys");
    }
}
