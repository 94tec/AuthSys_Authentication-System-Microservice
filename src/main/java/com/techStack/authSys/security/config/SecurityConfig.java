package com.techStack.authSys.security.config;

import com.techStack.authSys.security.authentication.FirebaseAuthFilter;
import com.techStack.authSys.security.authentication.FirebaseSecurityContextRepository;
import com.techStack.authSys.security.authentication.ForcePasswordChangeFilter;
import com.techStack.authSys.security.authorization.CustomAccessDeniedHandler;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final FirebaseSecurityContextRepository securityContextRepository;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final FirebaseAuthFilter firebaseAuthFilter;
    private final ForcePasswordChangeFilter forcePasswordChangeFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchange -> exchange
                        // ✅ Swagger UI (order matters - most specific first)
                        .pathMatchers(
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/webjars/**"
                        ).permitAll()

                        // ✅ Health and actuator
                        .pathMatchers("/actuator/**", "/health/**").permitAll()

                        // ✅ Static resources
                        .pathMatchers(
                                "/favicon.ico",
                                "/static/**",
                                "/css/**",
                                "/js/**",
                                "/images/**"
                        ).permitAll()

                        // ✅ Public authentication endpoints
                        .pathMatchers(
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/verify-email",
                                "/api/auth/resend-verification",
                                "/api/auth/check-email",
                                "/api/auth/logout",
                                "/api/auth/first-time-setup/**",
                                "/api/auth/login-otp/**",
                                "/api/otp/**",
                                "/api/v1/password-reset/**"
                        ).permitAll()

                        // ✅ Super Admin bootstrap (public)
                        .pathMatchers(
                                "/api/super-admin/register",
                                "/api/super-admin/login"
                        ).permitAll()

                        // ✅ Role-based access (order matters - most restrictive first)
                        .pathMatchers("/api/super-admin/**").hasRole("SUPER_ADMIN")
                        .pathMatchers("/api/tokens/**", "/api/logs/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/admin/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/manager/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers("/api/users/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN", "USER")

                        // ✅ All other endpoints require authentication
                        .anyExchange().authenticated()
                )
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .securityContextRepository(securityContextRepository)
                .addFilterAt(firebaseAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterAfter(forcePasswordChangeFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
    // ✅ CORS Configuration Source for WebFlux
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow specific origins
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",
                "http://localhost:3001",
                "http://localhost:3002"
        ));

        // Allow specific HTTP methods
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));

        // Allow all headers
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "X-Temp-Token",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
        ));

        // Expose headers to client
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type"
        ));

        // Allow credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);

        // Cache preflight response for 1 hour
        configuration.setMaxAge(3600L);

        // Apply to all paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy(
                "ROLE_SUPER_ADMIN > ROLE_ADMIN > ROLE_DESIGNER > ROLE_MANAGER > ROLE_USER > ROLE_GUEST"
        );
        return hierarchy;
    }

    @Bean
    public Bucket rateLimiter() {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(10, Refill.intervally(10, Duration.ofSeconds(1))))
                .build(); // ✅ Local bucket builder
    }
}