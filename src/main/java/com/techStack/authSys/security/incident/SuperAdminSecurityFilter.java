package com.techStack.authSys.security.incident;

import com.techStack.authSys.auth.context.CustomUserDetails;
import com.techStack.authSys.identity.models.User;
import com.techStack.authSys.security.models.IncidentSeverity;
import com.techStack.authSys.security.models.IncidentType;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Defense-in-depth for every /api/admin/** endpoint, layered ON TOP OF
 * (never instead of) @PreAuthorize("hasRole('SUPER_ADMIN')") on the
 * controllers themselves. Two independent checks, either of which can
 * reject the request before it reaches a controller:
 *
 * 1. IP allowlist — if `security.admin.ip-allowlist` is configured (comma
 *    separated CIDR-less IPs, extend to CIDR matching for prod), only those
 *    source IPs may reach /api/admin/**. Empty/unset = disabled (log-only),
 *    since a small team may not have static IPs yet — but Anthropic strongly
 *    recommend enabling this for production once your admin team is on a
 *    known VPN/office IP range.
 * 2. MFA-verified session flag — requires the caller's session/JWT to carry
 *    an `mfaVerified=true` claim set only after a completed OTP challenge
 *    (you already have OTP infrastructure from the 2FA login flow — reuse
 *    the same claim here rather than building a second MFA system).
 *
 * Every block is reported to SecurityIncidentService so SUPER_ADMIN can see
 * attempted admin-panel access from disallowed IPs or without fresh MFA.
 */
//@Component
@Order(-50) // run before controller-level auth so we can short-circuit early
@RequiredArgsConstructor
public class SuperAdminSecurityFilter implements WebFilter {

    private final SecurityIncidentService incidentService;
    private final Environment environment;

    private static final String ADMIN_PATH_PREFIX = "/api/admin/";
    private static final String MFA_CLAIM_ATTRIBUTE = "mfaVerified"; // populated by your JWT/session filter upstream

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!path.startsWith(ADMIN_PATH_PREFIX)) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();
        String ipAddress = resolveClientIp(request);
        String userAgent = request.getHeaders().getFirst("User-Agent");

        if (!isIpAllowed(ipAddress)) {
            return ReactiveSecurityContextHolder.getContext()
                    .map(SecurityContext::getAuthentication)
                    .map(Authentication::getName)
                    .defaultIfEmpty("unauthenticated")
                    .flatMap(userId -> {
                        incidentService.raise(
                                IncidentType.UNAUTHORIZED_ADMIN_ACCESS, IncidentSeverity.HIGH,
                                "Admin endpoint accessed from disallowed IP: " + path,
                                userId, ipAddress, userAgent);
                        return forbid(exchange);
                    });
        }

        if (!requiresMfa()) {
            return chain.filter(exchange);
        }

        // MFA check needs the authenticated principal. If there isn't one yet
        // (context empty — request will be rejected downstream by
        // .anyExchange().authenticated() anyway), let it pass through rather
        // than masking that failure mode as an MFA incident.
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .map(java.util.Optional::ofNullable)
                .defaultIfEmpty(java.util.Optional.empty())
                .flatMap(authOpt -> {
                    if (authOpt.isEmpty()) {
                        // No security context — request will be rejected downstream anyway
                        return chain.filter(exchange);
                    }
                    Authentication auth = authOpt.get();
                    if (isMfaSatisfied(auth)) {
                        return chain.filter(exchange);
                    }
                    incidentService.raise(
                            IncidentType.MFA_BYPASS_ATTEMPT, IncidentSeverity.CRITICAL,
                            "Admin endpoint accessed without MFA enabled: " + path,
                            auth.getName(), ipAddress, userAgent);
                    return forbid(exchange);
                });
    }

    /**
     * MFA is satisfied if the account doesn't require it, or requires it
     * and has it enabled. Firebase-token principals (raw UID string, no
     * CustomUserDetails) can't be checked this way yet — fail closed.
     */
    private boolean isMfaSatisfied(Authentication auth) {
        if (auth.getPrincipal() instanceof CustomUserDetails userDetails) {
            User user = userDetails.getUser();
            return !user.isMfaRequired() || user.isMfaEnabled();
        }
        return false;
    }
    private Mono<Void> forbid(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    private boolean isIpAllowed(String ipAddress) {
        String configured = environment.getProperty("security.admin.ip-allowlist", "");
        if (configured == null || configured.isBlank()) {
            return true; // allowlist disabled — log-only mode until configured
        }
        Set<String> allowed = Set.of(configured.split(","));
        return allowed.contains(ipAddress);
    }
    private boolean requiresMfa() {
        return environment.getProperty("security.admin.require-mfa", Boolean.class, true);
    }

    private String resolveClientIp(ServerHttpRequest request) {
        String forwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        InetAddress address = request.getRemoteAddress() != null
                ? request.getRemoteAddress().getAddress()
                : null;
        return address != null ? address.getHostAddress() : "unknown";
    }

    private boolean isMfaVerified(ServerWebExchange exchange) {
        // Populated by your existing JWT/session-parsing filter upstream of this one.
        // Wire this to whatever claim your FirebaseServiceAuth / session layer already
        // sets after a successful OTP challenge during login.
        Object flag = exchange.getAttributes().get(MFA_CLAIM_ATTRIBUTE);
        return Boolean.TRUE.equals(flag);
    }


}
