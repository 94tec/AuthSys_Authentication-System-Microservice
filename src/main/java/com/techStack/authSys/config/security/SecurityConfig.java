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
import org.springframework.beans.factory.annotation.Value;
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
import java.util.List;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final FirebaseSecurityContextRepository securityContextRepository;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;

    private final SecurityIncidentService securityIncidentService;
    private final Environment environment;
    private final Clock clock;

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

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
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // health only (Render and uptime checks); the rest of actuator is locked
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .pathMatchers("/actuator/**").hasRole("SUPER_ADMIN")

                        .pathMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**", "/webjars/**").permitAll() // consider removing in prod
                        .pathMatchers("/favicon.ico", "/static/**", "/css/**", "/js/**", "/images/**").permitAll()

                        // public auth
                        .pathMatchers(
                                "/api/auth/login", "/api/auth/register", "/api/auth/verify-email",
                                "/api/auth/resend-verification", "/api/auth/check-email", "/api/auth/logout",
                                "/api/auth/refresh", "/api/auth/first-time-setup/**", "/api/auth/login-otp/**",
                                "/api/otp/**", "/api/password-reset/**", "/api/auth/sso/redeem",
                                "/api/super-admin/register", "/api/super-admin/login"
                        ).permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/auth/sso/handoff-code").authenticated()

                        // most restrictive first
                        .pathMatchers("/api/super-admin/**", "/api/admin/security/**",
                                "/api/admin/database/**", "/api/admin/disaster-recovery/**").hasRole("SUPER_ADMIN")
                        .pathMatchers("/api/admin/bootstrap/**", "/api/admin/system/**",
                                "/api/admin/audit-logs/**", "/api/admin/access/**").hasAnyRole("SUPER_ADMIN", "ADMIN")

                        .pathMatchers(HttpMethod.GET, "/api/tours/admin/**").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER", "OPERATOR")
                        .pathMatchers(HttpMethod.GET, "/api/tours", "/api/tours/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/tours").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers(HttpMethod.PUT, "/api/tours/**").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers(HttpMethod.DELETE, "/api/tours/**").hasAnyRole("SUPER_ADMIN", "ADMIN")

                        .pathMatchers("/api/tokens/**", "/api/logs/**", "/api/admin/**",
                                "/api/payments/**", "/api/revenue/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/manager/**").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")

                        // customer-facing
                        .pathMatchers("/api/users/**", "/api/user/profile/**")
                        .hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER", "OPERATOR", "USER")
                        .pathMatchers(HttpMethod.POST, "/api/enquiries", "/api/bookings/my/**").hasRole("USER")

                        // everything else: staff only
                        .anyExchange().hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER", "OPERATOR")
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

        configuration.setAllowedOrigins(Arrays.asList(
                allowedOrigins.split(",")
        ));

        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));

        configuration.setAllowedHeaders(List.of("*"));

        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Refresh-Token"
        ));

        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

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