package com.techStack.authSys.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import com.techStack.authSys.models.auth.TokenClaimsModel;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.security.context.CustomUserDetails;
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
 */
@Slf4j
@Primary
@Service
@RequiredArgsConstructor
public class FirebaseAuthenticationManager implements ReactiveAuthenticationManager {

    /* =========================
       Constants
       ========================= */

    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final Duration AUTHENTICATION_TIMEOUT = Duration.ofSeconds(5);

    /* =========================
       Dependencies
       ========================= */

    private final JwtService jwtService;
    private final FirebaseTokenCacheService firebaseTokenCacheService;
    private final FirebaseServiceAuth firebaseServiceAuth;
    private final RedisUserCacheService redisCacheService;
    private final Clock clock;

    /* =========================
       Main Authentication
       ========================= */

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        Instant authStart = clock.instant();

        log.debug("Authentication attempt started at {}", authStart);

        return Mono.just(authentication)
                .flatMap(this::extractAndValidateToken)
                .flatMap(this::processToken)
                .doOnSuccess(auth -> {
                    Instant authEnd = clock.instant();
                    Duration authDuration = Duration.between(authStart, authEnd);

                    logSuccessfulAuthentication(auth, authEnd, authDuration);
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration errorDuration = Duration.between(authStart, errorTime);

                    log.error("❌ Authentication failed at {} after {}: {}",
                            errorTime, errorDuration, e.getMessage());
                })
                .onErrorResume(this::handleAuthenticationError);
    }

    /* =========================
       Token Extraction
       ========================= */

    /**
     * Extract and validate token from authentication object
     */
    private Mono<String> extractAndValidateToken(Authentication authentication) {
        Instant extractStart = clock.instant();

        return Mono.justOrEmpty(authentication.getCredentials())
                .cast(String.class)
                .filter(token -> !token.isBlank())
                .doOnSuccess(token -> {
                    if (token != null) {
                        Instant extractEnd = clock.instant();
                        Duration duration = Duration.between(extractStart, extractEnd);

                        log.debug("Token extracted at {} in {}", extractEnd, duration);
                    }
                })
                .switchIfEmpty(Mono.error(
                        new AuthenticationServiceException("Missing or empty token")
                ));
    }

    /* =========================
       Token Processing
       ========================= */

    /**
     * Process token based on its type
     */
    private Mono<Authentication> processToken(String token) {
        Instant processStart = clock.instant();

        return determineTokenType(token)
                .flatMap(tokenType -> {
                    log.debug("Processing {} token at {}", tokenType, clock.instant());

                    return switch (tokenType) {
                        case FIREBASE -> authenticateFirebaseToken(token)
                                .timeout(AUTHENTICATION_TIMEOUT);
                        case CUSTOM_JWT -> authenticateCustomJwt(token)
                                .timeout(AUTHENTICATION_TIMEOUT);
                    };
                })
                .doOnSuccess(auth -> {
                    Instant processEnd = clock.instant();
                    Duration duration = Duration.between(processStart, processEnd);

                    log.info("✅ Token processed successfully at {} in {}",
                            processEnd, duration);
                })
                .doOnError(e -> {
                    Instant errorTime = clock.instant();
                    Duration duration = Duration.between(processStart, errorTime);

                    log.error("❌ Token processing failed at {} after {}: {}",
                            errorTime, duration, e.getMessage());
                });
    }

    /**
     * Determine token type (Firebase or Custom JWT)
     */
    public Mono<TokenType> determineTokenType(String token) {
        Instant determineStart = clock.instant();

        return Mono.fromCallable(() -> {
                    if (isFirebaseToken(token)) return TokenType.FIREBASE;
                    if (isCustomJwt(token)) return TokenType.CUSTOM_JWT;
                    throw new AuthenticationServiceException("Unsupported token type");
                })
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(type -> {
                    Instant determineEnd = clock.instant();
                    Duration duration = Duration.between(determineStart, determineEnd);

                    log.debug("Token type determined as {} at {} in {}",
                            type, determineEnd, duration);
                });
    }

    /**
     * Check if token is a Firebase token
     */
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

    /**
     * Check if token is a Custom JWT
     */
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

    /* =========================
       Firebase Token Authentication
       ========================= */

    /**
     * Authenticate Firebase token
     */
    private Mono<Authentication> authenticateFirebaseToken(String token) {
        Instant authStart = clock.instant();

        return firebaseTokenCacheService.getCachedToken(token)
                .switchIfEmpty(Mono.defer(() -> verifyAndCacheFirebaseToken(token)))
                .map(this::createAuthentication)
                .doOnSuccess(auth -> {
                    Instant authEnd = clock.instant();
                    Duration duration = Duration.between(authStart, authEnd);

                    log.info("✅ Firebase token authenticated at {} in {}",
                            authEnd, duration);
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ Firebase token validation failed at {}: {}",
                            errorTime, e.getMessage());

                    return Mono.error(new AuthenticationServiceException(
                            "Firebase token validation failed: " + e.getMessage()
                    ));
                });
    }

    /**
     * Verify and cache Firebase token
     */
    public Mono<FirebaseToken> verifyAndCacheFirebaseToken(String token) {
        Instant verifyStart = clock.instant();

        return Mono.fromCallable(() -> FirebaseAuth.getInstance().verifyIdToken(token))
                .subscribeOn(Schedulers.boundedElastic())
                .doOnSuccess(decoded -> {
                    Instant verifyEnd = clock.instant();
                    Duration duration = Duration.between(verifyStart, verifyEnd);

                    log.info("Firebase token verified at {} in {} for UID: {}",
                            verifyEnd, duration, decoded.getUid());
                })
                .flatMap(decoded -> firebaseTokenCacheService
                        .cacheToken(token, decoded)
                        .thenReturn(decoded));
    }

    /**
     * Create authentication from Firebase token
     */
    private Authentication createAuthentication(FirebaseToken token) {
        return new UsernamePasswordAuthenticationToken(
                token.getUid(),
                null,
                extractAuthorities(token.getClaims())
        );
    }

    /* =========================
       Custom JWT Authentication
       ========================= */

    /**
     * Authenticate Custom JWT
     */
    private Mono<Authentication> authenticateCustomJwt(String token) {
        Instant authStart = clock.instant();

        return redisCacheService.getTokenClaims(token)
                .flatMap(this::castToClaimsMap)
                .switchIfEmpty(Mono.defer(() -> validateAndCacheFreshToken(token)))
                .flatMap(this::buildAuthentication)
                .doOnSuccess(auth -> {
                    Instant authEnd = clock.instant();
                    Duration duration = Duration.between(authStart, authEnd);

                    log.info("✅ Custom JWT authenticated at {} in {}",
                            authEnd, duration);
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.error("❌ JWT validation failed at {}: {}",
                            errorTime, e.getMessage());

                    Throwable ex = (e instanceof Throwable) ? (Throwable) e :
                            new RuntimeException("Unknown error");

                    return Mono.error(new AuthenticationServiceException(
                            "JWT validation failed: " + ex.getMessage()
                    ));
                });
    }

    /**
     * Validate and cache fresh token
     */
    public Mono<Map<String, Object>> validateAndCacheFreshToken(String token) {
        Instant validateStart = clock.instant();

        return jwtService.validateToken(token, CLAIM_TYPE_ACCESS)
                .doOnSuccess(claims -> {
                    Instant validateEnd = clock.instant();
                    Duration duration = Duration.between(validateStart, validateEnd);

                    log.debug("Token validated at {} in {}", validateEnd, duration);
                })
                .flatMap(claims -> cacheClaimsWithFallback(token, claims))
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.warn("Token validation failed at {}: {}", errorTime, e.getMessage());

                    return Mono.error(new AuthenticationServiceException("Invalid token"));
                });
    }

    /**
     * Cast claims to Map type
     */
    private Mono<Map<String, Object>> castToClaimsMap(Object claims) {
        return Mono.just(claims)
                .filter(Map.class::isInstance)
                .map(m -> (Map<String, Object>) m)
                .switchIfEmpty(Mono.error(
                        new AuthenticationServiceException("Invalid claims format")
                ));
    }


    /**
     * Cache claims with fallback
     */
    private Mono<Map<String, Object>> cacheClaimsWithFallback(
            String token,
            Map<String, Object> claims) {

        Instant cacheStart = clock.instant();

        return redisCacheService.cacheTokenClaims(token, claims)
                .doOnSuccess(success -> {
                    Instant cacheEnd = clock.instant();
                    Duration duration = Duration.between(cacheStart, cacheEnd);

                    log.debug("Claims cached at {} in {}", cacheEnd, duration);
                })
                .onErrorResume(e -> {
                    Instant errorTime = clock.instant();

                    log.warn("Failed to cache claims at {}: {} - Continuing with authentication",
                            errorTime, e.getMessage());

                    return Mono.empty();
                })
                .thenReturn(claims);
    }

    /* =========================
       Authentication Building
       ========================= */

    /**
     * Build authentication from claims
     */
    private Mono<Authentication> buildAuthentication(Map<String, Object> claims) {
        Instant buildStart = clock.instant();

        return Mono.fromCallable(() -> new TokenClaimsModel(claims))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(claimsModel -> {
                    String userIdentifier = claimsModel.getEmail()
                            .orElseGet(claimsModel::getUsername);

                    log.debug("Building authentication at {} for user: {}",
                            clock.instant(), HelperUtils.maskEmail(userIdentifier));

                    return firebaseServiceAuth.findByEmail(userIdentifier)
                            .switchIfEmpty(Mono.error(new AuthenticationServiceException(
                                    "User not found for identifier: " +
                                            HelperUtils.maskEmail(userIdentifier)
                            )))
                            .map(user -> {
                                // Sync forcePasswordChange from claims
                                boolean forceChange = Boolean.TRUE.equals(
                                        claims.get("forcePasswordChange")
                                );
                                user.setForcePasswordChange(forceChange);

                                log.debug("User loaded - forcePasswordChange: {}",
                                        user.isForcePasswordChange());

                                return createAuthenticationToken(user, claimsModel);
                            });
                })
                .doOnSuccess(auth -> {
                    Instant buildEnd = clock.instant();
                    Duration duration = Duration.between(buildStart, buildEnd);

                    log.debug("Authentication built at {} in {}", buildEnd, duration);
                });
    }

    /**
     * Create authentication token from user and claims
     */
    private Authentication createAuthenticationToken(User user, TokenClaimsModel claims) {
        Instant createStart = clock.instant();

        // Reload user to ensure fresh data
        User freshUser = firebaseServiceAuth.findByEmail(user.getEmail()).block();

        if (freshUser == null) {
            log.error("Failed to reload user: {}", HelperUtils.maskEmail(user.getEmail()));
            throw new AuthenticationServiceException("User reload failed");
        }

        log.debug("Creating authentication token at {} for user: {} - Roles: {} - forcePasswordChange: {}",
                clock.instant(),
                HelperUtils.maskEmail(freshUser.getEmail()),
                freshUser.getRoles(),
                freshUser.isForcePasswordChange());

        CustomUserDetails userDetails = new CustomUserDetails(
                freshUser,
                claims.getRoles(),
                claims.getPermissions()
        );

        Authentication auth = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        Instant createEnd = clock.instant();
        Duration duration = Duration.between(createStart, createEnd);

        log.debug("Authentication token created at {} in {}", createEnd, duration);

        return auth;
    }

    /* =========================
       Authority Extraction
       ========================= */

    /**
     * Extract authorities from claims
     */
    public Collection<GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Process roles
        extractRoles(claims).forEach(role ->
                authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role)));

        // Process permissions
        extractPermissions(claims).forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(PERM_PREFIX + perm)));

        return authorities.isEmpty()
                ? List.of(new SimpleGrantedAuthority(DEFAULT_ROLE))
                : authorities;
    }

    /**
     * Extract roles from claims
     */
    private Set<String> extractRoles(Map<String, Object> claims) {
        Set<String> roles = extractClaimSet(claims.get(CLAIM_ROLE));
        roles.addAll(extractClaimSet(claims.get(CLAIM_ROLES)));
        return roles;
    }

    /**
     * Extract permissions from claims
     */
    private Set<String> extractPermissions(Map<String, Object> claims) {
        Object raw = claims.get(CLAIM_PERMISSIONS);
        return extractClaimSet(raw);
    }

    /**
     * Extract claim set from various formats
     */
    private Set<String> extractClaimSet(Object claim) {
        if (claim instanceof String s) {
            return Arrays.stream(s.split(","))
                    .map(String::trim)
                    .filter(str -> !str.isEmpty())
                    .map(String::toUpperCase)
                    .collect(Collectors.toSet());
        } else if (claim instanceof List<?> list) {
            return list.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .map(String::toUpperCase)
                    .collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }

    /* =========================
       Logging & Error Handling
       ========================= */

    /**
     * Log successful authentication
     */
    private void logSuccessfulAuthentication(
            Authentication auth,
            Instant authTime,
            Duration authDuration) {

        String authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(", "));

        log.info("✅ Authenticated user at {} in {}: {} with authorities: {}",
                authTime,
                authDuration,
                auth.getName(),
                authorities);
    }

    /**
     * Handle authentication errors
     */
    private Mono<Authentication> handleAuthenticationError(Throwable e) {
        Instant errorTime = clock.instant();

        if (e instanceof AuthenticationServiceException) {
            log.error("Authentication service exception at {}: {}",
                    errorTime, e.getMessage());
            return Mono.error(e);
        }

        log.error("Unexpected authentication error at {}: {}",
                errorTime, e.getMessage(), e);

        return Mono.error(new AuthenticationServiceException(
                "Authentication failed", e
        ));
    }

    /* =========================
       Inner Classes
       ========================= */

    /**
     * Token type enumeration
     */
    private enum TokenType {
        FIREBASE,
        CUSTOM_JWT
    }
}