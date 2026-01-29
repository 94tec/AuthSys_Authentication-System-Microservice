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

import java.time.Duration;

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
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers(
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/api/super-admin/register",
                                "/api/super-admin/login",
                                "/api/auth/**",
                                "/api/register",
                                "/api/otp/**",
                                "/api/v1/password-reset/**"
                        ).permitAll()
                        .pathMatchers("/api/super-admin/**").hasRole("SUPER_ADMIN")
                        .pathMatchers("/api/tokens/**", "/api/logs/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
                        .pathMatchers("/api/manager/**").hasAnyRole("SUPER_ADMIN", "ADMIN", "MANAGER")
                        .pathMatchers("/api/users/**").hasAnyRole("SUPER_ADMIN", "ADMIN", "USER")
                        .pathMatchers("/api/admin/**").hasAnyRole("SUPER_ADMIN", "ADMIN")
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy(
                "ROLE_SUPER_ADMIN > ROLE_ADMIN > ROLE_MANAGER > ROLE_USER"
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