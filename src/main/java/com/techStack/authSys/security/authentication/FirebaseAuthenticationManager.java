package com.techStack.authSys.security.authentication;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.models.auth.TokenClaimsModel;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.security.context.CustomUserDetails;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.techStack.authSys.service.firebase.FirebaseTokenCacheService;
import com.techStack.authSys.service.token.JwtService;
import com.techStack.authSys.util.validation.HelperUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import static com.techStack.authSys.constants.SecurityConstants.*;

/**
 * Firebase Authentication Manager
 *
 * Handles authentication for both Firebase tokens and Custom JWT tokens.
 * Uses Clock for timestamp tracking and duration metrics.
 *
 * Fixes from original:
 *
 *   A. createAuthenticationToken() — called firebaseServiceAuth.findByEmail().block()
 *      inside a reactive flatMap chain. block() inside a reactive operator can deadlock
 *      on bounded thread pools and is forbidden in WebFlux. Removed the second load
 *      entirely — the user object already in scope is the freshly loaded one from
 *      buildAuthentication(). The "reload" was redundant and dangerous.
 *
 *   B. extractClaimSet() — applied .toUpperCase() to all claim values, including
 *      permission strings. Permission full names are lowercase namespace:action format
 *      e.g. "portfolio:publish". Uppercasing corrupts them so hasAuthority() checks
 *      against "PORTFOLIO:PUBLISH" never match the stored "portfolio:publish".
 *      Roles are correctly uppercased (ROLE_ADMIN). Permissions are now left as-is.
 *      The split is done by extractRoles() calling extractRoleClaimSet() and
 *      extractPermissions() calling extractPermissionClaimSet() — separate helpers
 *      with appropriate case handling for each.
 */
@Slf4j
@Primary
@Service
@RequiredArgsConstructor
public class FirebaseAuthenticationManager implements ReactiveAuthenticationManager {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Duration AUTHENTICATION_TIMEOUT = Duration.ofSeconds(5);

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private final JwtService jwtService;
    private final FirebaseTokenCacheService firebaseTokenCacheService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RedisUserCacheService redisCacheService;
    private final Clock clock;

    // -------------------------------------------------------------------------
    // Main Authentication
    // -------------------------------------------------------------------------

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        Instant authStart = clock.instant();

        log.debug("Authentication attempt started at {}", authStart);

        return Mono.just(authentication)
                .flatMap(this::extractAndValidateToken)
                .flatMap(this::processToken)
                .doOnSuccess(auth -> {
                    Duration authDuration = Duration.between(authStart, clock.instant());
                    logSuccessfulAuthentication(auth, clock.instant(), authDuration);
                })
                .doOnError(e -> log.error("❌ Authentication failed after {}: {}",
                        Duration.between(authStart, clock.instant()), e.getMessage()))
                .onErrorResume(this::handleAuthenticationError);
    }

    // -------------------------------------------------------------------------
    // Token Extraction
    // -------------------------------------------------------------------------

    private Mono<String> extractAndValidateToken(Authentication authentication) {
        Instant extractStart = clock.instant();

        return Mono.justOrEmpty(authentication.getCredentials())
                .cast(String.class)
                .filter(token -> !token.isBlank())
                .doOnSuccess(token -> {
                    if (token != null) {
                        log.debug("Token extracted in {}",
                                Duration.between(extractStart, clock.instant()));
                    }
                })
                .switchIfEmpty(Mono.error(
                        new AuthenticationServiceException("Missing or empty token")));
    }

    // -------------------------------------------------------------------------
    // Token Processing
    // -------------------------------------------------------------------------

    private Mono<Authentication> processToken(String token) {
        Instant processStart = clock.instant();

        return determineTokenType(token)
                .flatMap(tokenType -> {
                    log.debug("Processing {} token at {}", tokenType, clock.instant());
                    return switch (tokenType) {
                        case FIREBASE    -> authenticateFirebaseToken(token)
                                .timeout(AUTHENTICATION_TIMEOUT);
                        case CUSTOM_JWT  -> authenticateCustomJwt(token)
                                .timeout(AUTHENTICATION_TIMEOUT);
                    };
                })
                .doOnSuccess(__ -> log.info("✅ Token processed in {}",
                        Duration.between(processStart, clock.instant())))
                .doOnError(e -> log.error("❌ Token processing failed after {}: {}",
                        Duration.between(processStart, clock.instant()), e.getMessage()));
    }

    public Mono<TokenType> determineTokenType(String token) {
        Instant start = clock.instant();
        return Mono.fromCallable(() -> {
                    if (isFirebaseToken(token)) return TokenType.FIREBASE;
                    if (isCustomJwt(token))     return TokenType.CUSTOM_JWT;
                    throw new AuthenticationServiceException("Unsupported token type");
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(type -> log.debug("Token type {} determined in {}",
                        type, Duration.between(start, clock.instant())));
    }

    private boolean isFirebaseToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return false;

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode payload = objectMapper.readTree(payloadJson);

            return payload.has("iss") &&
                    payload.get("iss").asText().startsWith("https://securetoken.google.com/");
        } catch (Exception e) {
            log.debug("Failed to parse token as Firebase token: {}", e.getMessage());
            return false;
        }
    }

    private boolean isCustomJwt(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return false;

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode json = objectMapper.readTree(payload);

            return json.has(CLAIM_TYPE) &&
                    CLAIM_TYPE_ACCESS.equalsIgnoreCase(json.get(CLAIM_TYPE).asText());
        } catch (Exception e) {
            log.debug("Failed to parse token as Custom JWT: {}", e.getMessage());
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Firebase Token Authentication
    // -------------------------------------------------------------------------

    private Mono<Authentication> authenticateFirebaseToken(String token) {
        Instant start = clock.instant();

        return firebaseTokenCacheService.getCachedToken(token)
                .switchIfEmpty(Mono.defer(() -> verifyAndCacheFirebaseToken(token)))
                .map(this::createAuthentication)
                .doOnSuccess(__ -> log.info("✅ Firebase token authenticated in {}",
                        Duration.between(start, clock.instant())))
                .onErrorResume(e -> {
                    log.error("❌ Firebase token validation failed: {}", e.getMessage());
                    return Mono.error(new AuthenticationServiceException(
                            "Firebase token validation failed: " + e.getMessage()));
                });
    }

    public Mono<FirebaseToken> verifyAndCacheFirebaseToken(String token) {
        Instant start = clock.instant();

        return Mono.fromCallable(() -> FirebaseAuth.getInstance().verifyIdToken(token))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(decoded -> log.info("Firebase token verified in {} for UID: {}",
                        Duration.between(start, clock.instant()), decoded.getUid()))
                .flatMap(decoded -> firebaseTokenCacheService
                        .cacheToken(token, decoded)
                        .thenReturn(decoded));
    }

    private Authentication createAuthentication(FirebaseToken token) {
        return new UsernamePasswordAuthenticationToken(
                token.getUid(),
                null,
                extractAuthorities(token.getClaims())
        );
    }

    // -------------------------------------------------------------------------
    // Custom JWT Authentication
    // -------------------------------------------------------------------------

    private Mono<Authentication> authenticateCustomJwt(String token) {
        Instant start = clock.instant();

        return redisCacheService.getTokenClaims(token)
                .flatMap(this::castToClaimsMap)
                .switchIfEmpty(Mono.defer(() -> validateAndCacheFreshToken(token)))
                .flatMap(this::buildAuthentication)
                .doOnSuccess(__ -> log.info("✅ Custom JWT authenticated in {}",
                        Duration.between(start, clock.instant())))
                .onErrorResume(e -> {
                    log.error("❌ JWT validation failed: {}", e.getMessage());
                    return Mono.error(new AuthenticationServiceException(
                            "JWT validation failed: " + e.getMessage()));
                });
    }

    public Mono<Map<String, Object>> validateAndCacheFreshToken(String token) {
        Instant start = clock.instant();

        return jwtService.validateToken(token, CLAIM_TYPE_ACCESS)
                .doOnSuccess(__ -> log.debug("Token validated in {}",
                        Duration.between(start, clock.instant())))
                .flatMap(claims -> cacheClaimsWithFallback(token, claims))
                .onErrorResume(e -> {
                    log.warn("Token validation failed: {}", e.getMessage());
                    return Mono.error(new AuthenticationServiceException("Invalid token"));
                });
    }

    private Mono<Map<String, Object>> castToClaimsMap(Object claims) {
        return Mono.just(claims)
                .filter(Map.class::isInstance)
                .map(m -> (Map<String, Object>) m)
                .switchIfEmpty(Mono.error(
                        new AuthenticationServiceException("Invalid claims format")));
    }

    private Mono<Map<String, Object>> cacheClaimsWithFallback(
            String token, Map<String, Object> claims) {
        return redisCacheService.cacheTokenClaims(token, claims)
                .onErrorResume(e -> {
                    log.warn("Failed to cache claims: {} - continuing", e.getMessage());
                    return Mono.empty();
                })
                .thenReturn(claims);
    }

    // -------------------------------------------------------------------------
    // Authentication Building
    // -------------------------------------------------------------------------

    /**
     * Build a full Authentication from JWT claims.
     *
     * Loads the user once via findByEmail(), then builds CustomUserDetails
     * and the Authentication token directly from that loaded user.
     *
     * Fix from original:
     *   The original called findByEmail(user.getEmail()).block() a second time
     *   inside this method to get a "fresh" user. block() inside a reactive
     *   operator can deadlock a WebFlux thread pool. The second load was redundant —
     *   the user is already fresh from the flatMap above. Removed entirely.
     */
    private Mono<Authentication> buildAuthentication(Map<String, Object> claims) {
        Instant start = clock.instant();

        return Mono.fromCallable(() -> new TokenClaimsModel(claims))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(claimsModel -> {
                    String userIdentifier = claimsModel.getEmail()
                            .orElseGet(claimsModel::getUsername);

                    log.debug("Building authentication for user: {}",
                            HelperUtils.maskEmail(userIdentifier));

                    return firebaseServiceAuth.findByEmail(userIdentifier)
                            .switchIfEmpty(Mono.error(new AuthenticationServiceException(
                                    "User not found: " + HelperUtils.maskEmail(userIdentifier))))
                            .map(user -> {
                                // Sync forcePasswordChange from claims
                                boolean forceChange = Boolean.TRUE.equals(
                                        claims.get("forcePasswordChange"));
                                user.setForcePasswordChange(forceChange);

                                log.debug("User loaded: {} forcePasswordChange={}",
                                        HelperUtils.maskEmail(user.getEmail()),
                                        user.isForcePasswordChange());

                                // Build authentication directly from the loaded user.
                                // No second .block() needed — this user is already fresh.
                                CustomUserDetails userDetails = new CustomUserDetails(
                                        user,
                                        claimsModel.getRoles(),
                                        claimsModel.getPermissions()
                                );

                                return (Authentication) new UsernamePasswordAuthenticationToken(
                                        userDetails,
                                        null,
                                        userDetails.getAuthorities()
                                );
                            });
                })
                .doOnSuccess(__ -> log.debug("Authentication built in {}",
                        Duration.between(start, clock.instant())));
    }

    // -------------------------------------------------------------------------
    // Authority Extraction
    // -------------------------------------------------------------------------

    /**
     * Extract Spring Security authorities from a claims map.
     *
     * Roles are prefixed with ROLE_ and uppercased — Spring Security convention.
     * Permissions are left exactly as stored: lowercase namespace:action strings
     * e.g. "portfolio:publish". Uppercasing permissions would break hasAuthority()
     * checks since the stored strings are lowercase.
     */
    public Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Roles → ROLE_ADMIN style (uppercase is correct for roles)
        extractRoles(claims).forEach(role ->
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));

        // Permissions → "portfolio:publish" style (lowercase, must NOT be uppercased)
        extractPermissions(claims).forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(PERM_PREFIX + perm)));

        return authorities.isEmpty()
                ? List.of(new SimpleGrantedAuthority(DEFAULT_ROLE))
                : authorities;
    }

    private Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = extractRoleClaimSet(claims.get(CLAIM_ROLE));
        roles.addAll(extractRoleClaimSet(claims.get(CLAIM_ROLES)));
        return roles;
    }

    private Set<String> extractPermissions(Map<String, Object> claims) {
        return extractPermissionClaimSet(claims.get(CLAIM_PERMISSIONS));
    }

    /**
     * Extract role claim values and uppercase them.
     * Roles are stored as names (ADMIN, USER) or may come in lowercase — normalise to upper.
     */
    private Set<String> extractRoleClaimSet(Object claim) {
        return extractRawClaimSet(claim).stream()
                .map(String::toUpperCase)
                .collect(Collectors.toSet());
    }

    /**
     * Extract permission claim values WITHOUT uppercasing.
     * Permissions are "portfolio:publish" format — case must be preserved exactly.
     */
    private Set<String> extractPermissionClaimSet(Object claim) {
        return extractRawClaimSet(claim);
    }

    /**
     * Extract string values from a claim that may be a comma-delimited String or a Collection.
     * Does NOT apply any case transformation — callers are responsible for case.
     */
    private Set<String> extractRawClaimSet(Object claim) {
        if (claim instanceof String s) {
            return Arrays.stream(s.split(","))
                    .map(String::trim)
                    .filter(str -> !str.isEmpty())
                    .collect(Collectors.toSet());
        }
        if (claim instanceof Collection<?> list) {
            return list.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }

    // -------------------------------------------------------------------------
    // Logging & Error Handling
    // -------------------------------------------------------------------------

    private void logSuccessfulAuthentication(
            Authentication auth, Instant authTime, Duration authDuration) {
        String authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(", "));

        log.info("✅ Authenticated {} at {} in {} — authorities: {}",
                auth.getName(), authTime, authDuration, authorities);
    }

    private Mono<Authentication> handleAuthenticationError(Throwable e) {
        if (e instanceof AuthenticationServiceException) {
            log.error("Authentication service exception: {}", e.getMessage());
            return Mono.error(e);
        }
        log.error("Unexpected authentication error: {}", e.getMessage(), e);
        return Mono.error(new AuthenticationServiceException("Authentication failed", e));
    }

    // -------------------------------------------------------------------------
    // Inner Types
    // -------------------------------------------------------------------------

    private enum TokenType {
        FIREBASE,
        CUSTOM_JWT
    }
}