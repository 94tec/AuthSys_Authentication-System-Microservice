package com.techStack.authSys.config.security;

import com.techStack.authSys.auth.filter.CustomAccessDeniedHandler;
import com.techStack.authSys.auth.filter.FirebaseAuthFilter;
import com.techStack.authSys.auth.filter.ForcePasswordChangeFilter;
import com.techStack.authSys.auth.firebase.FirebaseSecurityContextRepository;
import com.techStack.authSys.security.incident.SecurityIncidentService;
import com.techStack.authSys.security.incident.SuperAdminSecurityFilter;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
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

import java.time.Clock;
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
    //private final FirebaseAuthFilter firebaseAuthFilter;
    //private final SuperAdminSecurityFilter superAdminSecurityFilter;
    //private final ForcePasswordChangeFilter forcePasswordChangeFilter;

    private final SecurityIncidentService securityIncidentService;
    private final Environment environment;
    private final Clock clock;

    @Bean
    public FirebaseAuthFilter firebaseAuthFilter(
            RateLimitProperties rateLimitProperties,
            MeterRegistry meterRegistry,
            Clock clock
    ) {
        return new FirebaseAuthFilter(rateLimitProperties, meterRegistry, clock);
    }

    @Bean
    public ForcePasswordChangeFilter forcePasswordChangeFilter() {
        return new ForcePasswordChangeFilter(clock);
    }

    @Bean
    public SuperAdminSecurityFilter superAdminSecurityFilter() {
        return new SuperAdminSecurityFilter(securityIncidentService, environment);
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            FirebaseAuthFilter firebaseAuthFilter,
            ForcePasswordChangeFilter forcePasswordChangeFilter,
            SuperAdminSecurityFilter superAdminSecurityFilter
    ) {
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
                                "/api/auth/refresh",
                                "/api/auth/first-time-setup/**",
                                "/api/auth/login-otp/**",
                                "/api/otp/**",
                                "/api/password-reset/**",

                                "/api/auth/sso/handoff-code", // still needs auth — this is fine as-is
                                "/api/auth/sso/redeem"

                        ).permitAll()

                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/favicon.ico").permitAll()
                        // ✅ Super Admin bootstrap (public)
                        .pathMatchers(
                                "/api/super-admin/register",
                                "/api/super-admin/login"
                        ).permitAll()

                        // ✅ Role-based access (order matters - most restrictive first)
                        .pathMatchers("/api/super-admin/**").hasRole("SUPER_ADMIN")
                        .pathMatchers("/api/admin/bootstrap/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/admin/system/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/admin/database/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/admin/audit-logs/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/admin/access/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/admin/security/**").hasRole("SUPER_ADMIN")
                        .pathMatchers("/api/admin/database/**").hasRole("SUPER_ADMIN")
                        .pathMatchers("/api/admin/disaster-recovery/**").hasRole("SUPER_ADMIN")

                        .pathMatchers(HttpMethod.GET, "/api/tours/admin/**").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers(HttpMethod.GET, "/api/tours/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/tours").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers(HttpMethod.PUT, "/api/tours/**").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers(HttpMethod.DELETE, "/api/tours/**").hasAnyRole("SUPER_ADMIN", "ADMIN")

                        .pathMatchers("/api/tokens/**", "/api/logs/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/admin/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/manager/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers("/api/users/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN", "USER")
                        .pathMatchers("/api/user/profile/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN", "USER")

                        // ✅ All other endpoints require authentication
                        .anyExchange().authenticated()
                )
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .securityContextRepository(securityContextRepository)
                .addFilterBefore(firebaseAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterAfter(forcePasswordChangeFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .addFilterAfter(superAdminSecurityFilter, SecurityWebFiltersOrder.AUTHENTICATION)
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
                "ROLE_SUPER_ADMIN > ROLE_ADMIN > ROLE_OPERATOR > ROLE_MANAGER > ROLE_USER > ROLE_GUEST"
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