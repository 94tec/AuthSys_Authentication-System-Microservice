package com.techStack.authSys.security.sso;

import com.techStack.authSys.auth.jwt.TokenGenerationService;
import com.techStack.authSys.auth.service.FirebaseServiceAuth;
import com.techStack.authSys.authorization.repository.PermissionProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth/sso")
@RequiredArgsConstructor
public class SsoHandoffController {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final TokenGenerationService tokenGenerationService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final PermissionProvider permissionProvider;

    private static final Duration CODE_TTL = Duration.ofSeconds(30);
    private static final String KEY_PREFIX = "sso:handoff:";

    @PostMapping("/handoff-code")
    @PreAuthorize("isAuthenticated()")
    public Mono<ResponseEntity<Map<String, String>>> createHandoffCode(Authentication authentication) {
        String userId = authentication.getName();
        String code = UUID.randomUUID().toString();
        String key = KEY_PREFIX + code;

        return redisTemplate.opsForValue()
                .set(key, userId, CODE_TTL)
                .doOnSuccess(ok -> log.info("🔗 SSO handoff code issued for {} (expires in {}s)", userId, CODE_TTL.getSeconds()))
                .map(ok -> ResponseEntity.ok(Map.of("code", code, "expiresInSeconds", String.valueOf(CODE_TTL.getSeconds()))));
    }

    /**
     * Redeem an SSO handoff code for a real token pair.
     *
     * generateAndPersistTokens() needs the full User plus request-time
     * context (ip/device/user-agent) and resolved permissions — none of
     * that survives from the original portal's request, nor should it:
     * the session being minted belongs to *this* request, on the
     * receiving portal, so its IP/user-agent are used instead.
     */
    @PostMapping("/redeem")
    public Mono<ResponseEntity<Map<String, Object>>> redeem(
            @RequestBody Map<String, String> body,
            ServerWebExchange exchange) {

        String code = body.get("code");
        if (code == null || code.isBlank()) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of("error", "Missing code")));
        }
        String key = KEY_PREFIX + code;

        String ipAddress = exchange.getRequest().getRemoteAddress() != null
                ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                : "UNKNOWN";
        String userAgent = exchange.getRequest().getHeaders().getFirst("User-Agent");
        // No stable device fingerprint is available for a cross-portal handoff request —
        // this is a deliberate placeholder, not a full fingerprinting implementation.
        String deviceFingerprint = "sso-handoff";

        return redisTemplate.opsForValue().get(key)
                .flatMap(userId -> redisTemplate.delete(key).thenReturn(userId))
                .flatMap(firebaseServiceAuth::findByEmail)   // ← was getUserById
                .flatMap(user -> {
                    var permissions = new ArrayList<>(permissionProvider.resolveEffectivePermissions(user));
                    return tokenGenerationService.generateAndPersistTokens(
                            user, ipAddress, deviceFingerprint, userAgent, permissions);
                })
                .map(authResult -> ResponseEntity.ok(Map.<String, Object>of(
                        "accessToken", authResult.getAccessToken(),
                        "refreshToken", authResult.getRefreshToken()
                )))
                .doOnSuccess(r -> log.info("✅ SSO handoff redeemed"))
                .switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid, expired, or already-used code"))));
    }
}