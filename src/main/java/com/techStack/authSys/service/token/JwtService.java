package com.techStack.authSys.service.token;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.*;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import com.google.firebase.auth.UserRecord;
import com.techStack.authSys.config.security.JwtConfig;
import com.techStack.authSys.exception.service.CustomException;
import com.techStack.authSys.models.auth.*;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.security.EncryptionService;
import com.techStack.authSys.util.firebase.FirestoreUtil;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    // Constants
    private static final String COLLECTION_REFRESH_TOKENS = "refresh_tokens";
    private static final String TOKEN_TYPE_ACCESS = "access";
    private static final String TOKEN_TYPE_REFRESH = "refresh";
    private static final String TOKEN_TYPE_EMAIL_VERIFICATION = "email_verification";
    private static final String COLLECTION_REVOKED_TOKENS = "revoked_tokens";
    private static final String COLLECTION_BLACKLISTED_TOKENS = "blacklisted_tokens";

    // Dependencies
    private final Firestore firestore;
    private final AuditLogService auditLogService;
    private final FirebaseAuth firebaseAuth;
    private final JwtConfig jwtConfig;
    private final Environment environment;
    private final EncryptionService encryptionService;

    // ✅ FIXED: Simplified to avoid duplicate logic
    public Mono<TokenPair> generateTokenPair(User user, String ipAddress, String userAgent, Set<String> permissions) {
        return generateTokenPairWithExpiry(user, ipAddress, userAgent, permissions)
                .map(components -> new TokenPair(
                        components.getAccessToken(),
                        components.getRefreshToken()
                ));
    }

    public Mono<TokenComponentsWithExpiry> generateTokenPairWithExpiry(User user, String ipAddress,
                                                                       String userAgent, Set<String> permissions) {
        Instant now = Instant.now();

        return verifyFirebaseUser(user.getId())
                .flatMap(firebaseToken -> generateTokenComponents(user, ipAddress, userAgent, now, permissions))
                .flatMap(components -> storeRefreshToken(components, now))
                .doOnSuccess(pair -> logTokenGenerationSuccess(user, ipAddress))
                .doOnError(e -> logTokenGenerationFailure(user, ipAddress, e))
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ✅ FIXED: Now correctly parses tokens without type enforcement
    public Mono<Claims> parseToken(String token) {
        return Mono.fromCallable(() -> {
                    try {
                        // Try access token key first
                        return Jwts.parserBuilder()
                                .setSigningKey(jwtConfig.accessTokenSecretKey())
                                .setAllowedClockSkewSeconds(60)
                                .build()
                                .parseClaimsJws(token)
                                .getBody();
                    } catch (JwtException e) {
                        // Try refresh token key if access key fails
                        return Jwts.parserBuilder()
                                .setSigningKey(jwtConfig.refreshTokenSecretKey())
                                .setAllowedClockSkewSeconds(60)
                                .build()
                                .parseClaimsJws(token)
                                .getBody();
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(e -> new CustomException(
                        HttpStatus.UNAUTHORIZED,
                        "Failed to parse token: " + e.getMessage()
                ));
    }

    /**
     * Retrieves the expiration time of a refresh token
     */
    public Mono<Instant> getRefreshTokenExpiry(String refreshToken) {
        return getTokenExpiry(refreshToken, TOKEN_TYPE_REFRESH);
    }

    /**
     * Retrieves the expiration time of an access token
     */
    public Mono<Instant> getAccessTokenExpiry(String accessToken) {
        return getTokenExpiry(accessToken, TOKEN_TYPE_ACCESS);
    }

    /**
     * Shared implementation for getting token expiry
     */
    private Mono<Instant> getTokenExpiry(String token, String tokenType) {
        return validateToken(token, tokenType)
                .map(claims -> claims.getExpiration().toInstant())
                .onErrorMap(e -> new CustomException(
                        HttpStatus.UNAUTHORIZED,
                        String.format("Invalid %s token: %s", tokenType, e.getMessage())
                ));
    }

    public Mono<String> verifyFirebaseUser(String userId) {
        return Mono.fromCallable(() -> {
                    UserRecord userRecord = firebaseAuth.getUser(userId);
                    logger.info("Firebase verification for user ID {} successful", userId);
                    return userRecord.getUid();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    logger.error("Firebase user verification failed for user {}", userId, e);
                    return Mono.error(new CustomException(
                            HttpStatus.NOT_FOUND,
                            "User not found in Firebase"
                    ));
                });
    }

    public Mono<TokenComponentsWithExpiry> generateTokenComponents(User user, String ipAddress,
                                                                   String userAgent, Instant issuedAt,
                                                                   Set<String> permissions) {
        return Mono.fromCallable(() -> {
                    String accessToken = generateAccessToken(user, ipAddress, userAgent, issuedAt, permissions);
                    String refreshToken = generateRefreshToken(user, ipAddress, userAgent, issuedAt, permissions);

                    Instant accessTokenExpiry = issuedAt.plusSeconds(jwtConfig.getAccessTokenExpirationInSeconds());
                    Instant refreshTokenExpiry = issuedAt.plusSeconds(jwtConfig.getRefreshTokenExpirationInSeconds());

                    return TokenComponentsWithExpiry.builder()
                            .userId(user.getId())
                            .tokenPair(new TokenPair(accessToken, refreshToken))
                            .accessTokenExpiry(accessTokenExpiry)
                            .refreshTokenExpiry(refreshTokenExpiry)
                            .ipAddress(ipAddress)
                            .userAgent(userAgent)
                            .build();
                }).subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> {
                    logger.error("Token generation failed for user {}", user.getId(), e);
                    return Mono.error(new CustomException(
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "Token generation failed"
                    ));
                });
    }

    private String generateAccessToken(User user, String ipAddress, String userAgent,
                                       Instant issuedAt, Set<String> permissions) {
        Map<String, Object> claims = buildEnhancedClaims(user, ipAddress, userAgent,
                TOKEN_TYPE_ACCESS, permissions);

        return jwtConfig.jwtBuilder()
                .setClaims(claims)
                .setSubject(user.getId())
                .setIssuer(jwtConfig.getIssuer())
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(issuedAt.plusSeconds(jwtConfig.getAccessTokenExpirationInSeconds())))
                .signWith(jwtConfig.accessTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private String generateRefreshToken(User user, String ipAddress, String userAgent,
                                        Instant issuedAt, Set<String> permissions) {
        Map<String, Object> claims = buildEnhancedClaims(user, ipAddress, userAgent,
                TOKEN_TYPE_REFRESH, permissions);
        String jti = UUID.randomUUID().toString();
        claims.put("jti", jti);

        return jwtConfig.refreshTokenJwtBuilder()
                .setClaims(claims)
                .setSubject(user.getId())
                .setIssuer(jwtConfig.getIssuer())
                .setId(jti)
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(issuedAt.plusSeconds(jwtConfig.getRefreshTokenExpirationInSeconds())))
                .signWith(jwtConfig.refreshTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    private Map<String, Object> buildEnhancedClaims(User user, String ipAddress,
                                                    String userAgent, String tokenType,
                                                    Set<String> permissions) {
        Map<String, Object> claims = new HashMap<>();

        // Core identity claims
        claims.put("userId", user.getId());
        claims.put("email", user.getEmail());
        claims.put("type", tokenType);

        // Security context claims
        claims.put("ipAddress", ipAddress);
        claims.put("userAgent", userAgent);
        claims.put("authTime", Instant.now().getEpochSecond());

        // Authorization claims
        claims.put("roles", user.getRoles());
        claims.put("permissions", new ArrayList<>(permissions));

        // Additional metadata
        claims.put("fullName", formatFullName(user.getFirstName(), user.getLastName()));
        claims.put("mfaEnabled", user.isMfaRequired());
        claims.put("deviceId", user.getDeviceFingerprint());

        return claims;
    }

    public Mono<TokenComponentsWithExpiry> storeRefreshToken(TokenComponentsWithExpiry components,
                                                             Instant issuedAt) {
        if (components == null || components.getRefreshToken() == null) {
            return Mono.error(new IllegalArgumentException("Token components cannot be null"));
        }

        return validateRefreshToken(components.getRefreshToken(), components.getUserId())
                .flatMap(claims -> {
                    // Hash the refresh token before storing
                    String tokenHash = encryptionService.hashToken(components.getRefreshToken());
                    RefreshTokenRecord record = RefreshTokenRecord.builder()
                            .tokenId(claims.getId())
                            .userId(components.getUserId())
                            .tokenHash(tokenHash)
                            .ipAddress(components.getIpAddress())
                            .userAgent(components.getUserAgent())
                            .issuedAt(issuedAt)
                            .expiresAt(claims.getExpiration().toInstant())
                            .revoked(false)
                            .build();

                    return storeRefreshTokenRecord(record)
                            .thenReturn(components);
                })
                .onErrorResume(e -> handleStorageError(e, components.getUserId()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Void> storeRefreshTokenRecord(RefreshTokenRecord record) {
        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(
                        firestore.collection(COLLECTION_REFRESH_TOKENS)
                                .document(record.getTokenId())
                                .set(record)
                ))
                .timeout(Duration.ofSeconds(5))
                .doOnSuccess(__ -> logger.info("Refresh token stored for user {}", record.getUserId()))
                .onErrorMap(e -> new CustomException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to store refresh token",
                        e))
                .then();
    }

    public Mono<Claims> validateRefreshToken(String token, String expectedUserId) {
        return validateToken(token, TOKEN_TYPE_REFRESH)
                .flatMap(claims -> {
                    if (!expectedUserId.equals(claims.getSubject())) {
                        return Mono.error(new JwtException("Token subject does not match user ID"));
                    }
                    return Mono.just(claims);
                });
    }

    public Mono<Claims> validateRefreshToken(String token) {
        return validateToken(token, TOKEN_TYPE_REFRESH);
    }

    private Mono<User> verifyTokenContext(Claims claims, String ipAddress, String userAgent, User user) {
        return Mono.fromCallable(() -> {
            String tokenIp = claims.get("ipAddress", String.class);
            String tokenUserAgent = claims.get("userAgent", String.class);

            if (!shouldEnforceIpValidation() || StringUtils.equals(tokenIp, ipAddress)) {
                // IP validation is disabled or matches
            } else {
                logger.warn("IP address changed from {} to {}", tokenIp, ipAddress);
                throw new CustomException(HttpStatus.UNAUTHORIZED, "Token context invalid - IP mismatch");
            }

            if (!StringUtils.equals(tokenUserAgent, userAgent)) {
                logger.warn("User-Agent changed from {} to {}", tokenUserAgent, userAgent);
                throw new CustomException(HttpStatus.UNAUTHORIZED, "Token context invalid - User-Agent mismatch");
            }

            return user;
        });
    }

    public Mono<TokenPair> refreshTokens(String refreshToken, String ipAddress,
                                         String userAgent, Set<String> permissions) {
        if (StringUtils.isBlank(refreshToken)) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Refresh token is required"));
        }

        return Mono.defer(() -> validateRefreshToken(refreshToken))
                .flatMap(claims -> processValidRefreshToken(claims, ipAddress, userAgent, permissions))
                .doOnSuccess(tokens -> logRefreshSuccess(tokens, ipAddress))
                .doOnError(e -> logRefreshFailure(e, ipAddress))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<TokenPair> processValidRefreshToken(Claims claims, String ipAddress,
                                                     String userAgent, Set<String> permissions) {
        return checkTokenRevocationStatus(claims.getId())
                .then(retrieveUserFromClaims(claims))
                .flatMap(user -> verifyTokenContext(claims, ipAddress, userAgent, user))
                .flatMap(user -> generateNewTokenPair(user, ipAddress, userAgent, permissions))
                .flatMap(tokenPair -> revokeOldToken(claims.getId(), tokenPair).thenReturn(tokenPair));
    }

    private Mono<TokenComponentsWithExpiry> handleStorageError(Throwable e, String userId) {
        log.error("Failed to store refresh token for user {}", userId, e);

        if (e instanceof TimeoutException) {
            return Mono.error(new CustomException(
                    HttpStatus.REQUEST_TIMEOUT,
                    "Refresh token storage timed out"
            ));
        }
        else if (e instanceof JwtException) {
            return Mono.error(new CustomException(
                    HttpStatus.BAD_REQUEST,
                    String.format("Invalid refresh token: %s", e.getMessage())
            ));
        }
        else if (e instanceof FirestoreException) {
            return Mono.error(new CustomException(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Database unavailable for token storage"
            ));
        }

        return Mono.error(new CustomException(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Failed to store refresh token"
        ));
    }

    // Token validation methods
    public TokenValidationResult validateAccessToken(String token, String ipAddress) {
        if (StringUtils.isBlank(token)) {
            logger.warn("Empty token provided for validation");
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Authorization token is required");
        }

        try {
            Claims claims = validateJwtStructure(token);
            checkTokenRevocationStatus(claims);
            validateTokenContext(claims, ipAddress);
            return buildValidationResult(claims, true, "Valid token");

        } catch (ExpiredJwtException e) {
            logger.warn("Expired token detected for subject: {}", e.getClaims().getSubject());
            auditLogService.logSecurityEvent(
                    "TOKEN_VALIDATION_FAILURE",
                    e.getClaims().getSubject(),
                    Map.of("reason", "expired", "ip", ipAddress).toString()
            );
            return buildValidationResult(e.getClaims(), false, "Token expired");

        } catch (JwtException e) {
            logger.warn("Invalid access token: {}", e.getMessage());
            auditLogService.logSecurityEvent(
                    "TOKEN_VALIDATION_FAILURE",
                    "unknown",
                    Map.of("reason", "invalid", "error", e.getMessage(), "ip", ipAddress).toString()
            );
            throw new CustomException(HttpStatus.UNAUTHORIZED, "Invalid access token");
        }
    }

    private Claims validateJwtStructure(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(jwtConfig.accessTokenSecretKey())
                .setAllowedClockSkewSeconds(60)
                .requireIssuer(jwtConfig.getIssuer())
                .require("type", TOKEN_TYPE_ACCESS)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private void checkTokenRevocationStatus(Claims claims) {
        if (isTokenRevoked(claims.getId())) {
            logger.warn("Attempt to use revoked token: {}", claims.getId());
            throw new JwtException("Token has been revoked");
        }
    }

    private boolean isTokenRevoked(String jti) {
        try {
            DocumentSnapshot doc = firestore.collection(COLLECTION_REVOKED_TOKENS)
                    .document(jti)
                    .get()
                    .get(2, TimeUnit.SECONDS);
            return doc.exists();
        } catch (Exception e) {
            logger.error("Error checking token revocation status", e);
            return true; // Fail secure
        }
    }

    private FirebaseToken verifyFirebaseToken(String token, String expectedUid) throws FirebaseAuthException {
        FirebaseToken firebaseToken = firebaseAuth.verifyIdToken(token, true);

        if (!firebaseToken.getUid().equals(expectedUid)) {
            logger.error("Firebase UID mismatch: expected {} got {}", expectedUid, firebaseToken.getUid());
            throw new JwtException("Identity mismatch between JWT and Firebase");
        }

        if (isTokenRevokedInDatabase(firebaseToken.getUid())) {
            logger.warn("Revoked Firebase token detected for UID: {}", expectedUid);
            throw new JwtException("Firebase token has been revoked");
        }

        return firebaseToken;
    }

    private boolean isTokenRevokedInDatabase(String uid) {
        try {
            DocumentSnapshot doc = firestore.collection(COLLECTION_REVOKED_TOKENS)
                    .document(uid)
                    .get()
                    .get(2, TimeUnit.SECONDS);
            return doc.exists();
        } catch (Exception e) {
            logger.error("Error checking token revocation status", e);
            return true;
        }
    }

    private void validateTokenContext(Claims claims, String currentIp) {
        if (!shouldEnforceIpValidation()) {
            return;
        }

        String tokenIp = claims.get("ipAddress", String.class);
        if (!StringUtils.equals(tokenIp, currentIp)) {
            logger.warn("IP address mismatch: token [{}], current [{}]", tokenIp, currentIp);
            throw new JwtException("Token context invalid - IP mismatch");
        }
    }

    private TokenValidationResult buildValidationResult(Claims claims, boolean isValid, String message) {
        return TokenValidationResult.builder()
                .subject(claims.getSubject())
                .userId(claims.get("userId", String.class))
                .email(claims.get("email", String.class))
                .roles(claims.get("roles", List.class))
                .permissions(claims.get("permissions", List.class))
                .issuedAt(claims.getIssuedAt().toInstant())
                .expiration(claims.getExpiration().toInstant())  // Changed from expiresAt to expiration
                .valid(isValid)
                .message(message)
                .mfaEnabled(claims.get("mfaEnabled", Boolean.class))
                .build();
    }

    private Mono<Void> checkTokenRevocationStatus(String jti) {
        return Mono.fromCallable(() ->
                firestore.collection(COLLECTION_REVOKED_TOKENS)
                        .document(jti)
                        .get()
                        .get(2, TimeUnit.SECONDS)
        ).flatMap(document -> {
            if (document.exists()) {
                return Mono.error(new CustomException(
                        HttpStatus.UNAUTHORIZED,
                        "Refresh token has been revoked"
                ));
            }
            return Mono.empty();
        }).onErrorResume(e -> {
            logger.error("Error checking token revocation status", e);
            return Mono.error(new CustomException(
                    HttpStatus.UNAUTHORIZED,
                    "Unable to verify token status"
            ));
        }).then();
    }

    private Mono<User> retrieveUserFromClaims(Claims claims) {
        return Mono.fromCallable(() -> {
                    String userId = claims.getSubject();
                    DocumentSnapshot userDoc = firestore.collection("users")
                            .document(userId)
                            .get()
                            .get(2, TimeUnit.SECONDS);

                    if (!userDoc.exists()) {
                        throw new CustomException(HttpStatus.NOT_FOUND, "User not found");
                    }

                    return User.builder()
                            .id(userId)
                            .email(userDoc.getString("email"))
                            .roleNames(userDoc.get("roles", List.class))
                            .firstName(userDoc.getString("firstName"))
                            .lastName(userDoc.getString("lastName"))
                            .mfaRequired(Boolean.TRUE.equals(userDoc.getBoolean("mfaRequired")))
                            .deviceFingerprint(userDoc.getString("deviceFingerprint"))
                            .build();
                }).subscribeOn(Schedulers.boundedElastic())
                .onErrorResume(e -> Mono.error(
                        new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to retrieve user")
                ));
    }

    private Mono<TokenPair> generateNewTokenPair(User user, String ipAddress,
                                                 String userAgent, Set<String> permissions) {
        return generateTokenPair(user, ipAddress, userAgent, permissions)
                .timeout(Duration.ofSeconds(5))
                .onErrorMap(e -> new CustomException(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Failed to generate new tokens"
                ));
    }

    private Mono<Void> revokeOldToken(String jti, TokenPair newTokens) {
        return Mono.fromRunnable(() -> {
            try {
                firestore.collection(COLLECTION_REVOKED_TOKENS)
                        .document(jti)
                        .set(Map.of(
                                "revokedAt", FieldValue.serverTimestamp(),
                                "replacedBy", newTokens.getRefreshToken()
                        ))
                        .get(2, TimeUnit.SECONDS);
            } catch (Exception e) {
                logger.error("Failed to revoke old refresh token", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    // Logging methods
    public void logTokenGenerationSuccess(User user, String ipAddress) {
        logger.info("Successfully generated tokens for user {} from IP {}", user.getId(), ipAddress);
        auditLogService.logSecurityEvent(
                "TOKEN_GENERATION",
                user.getId(),
                Map.of("ipAddress", ipAddress, "status", "success").toString()
        );
    }

    public void logTokenGenerationFailure(User user, String ipAddress, Throwable e) {
        logger.error("Token generation failed for user {} from IP {}", user.getId(), ipAddress, e);
        auditLogService.logSecurityEvent(
                "TOKEN_GENERATION_FAILURE",
                user.getId(),
                Map.of(
                        "ipAddress", ipAddress,
                        "error", e.getMessage(),
                        "status", "failed"
                ).toString()
        );
    }

    private void logRefreshSuccess(TokenPair tokens, String ipAddress) {
        logger.info("Successfully refreshed tokens for IP {}", ipAddress);
        auditLogService.logSecurityEvent(
                "TOKEN_REFRESH",
                tokens.getAccessToken().substring(0, Math.min(10, tokens.getAccessToken().length())) + "...",
                Map.of("ipAddress", ipAddress, "status", "success").toString()
        );
    }

    private void logRefreshFailure(Throwable e, String ipAddress) {
        logger.error("Token refresh failed for IP {}", ipAddress, e);
        auditLogService.logSecurityEvent(
                "TOKEN_REFRESH_FAILURE",
                ipAddress,
                Map.of(
                        "error", e.getMessage(),
                        "status", "failed",
                        "type", e instanceof CustomException ? "validation" : "system"
                ).toString()
        );
    }

    // Token revocation methods
    public Mono<Void> revokeTokensForIp(String userId, String ipAddress, String revokedBy) {
        if (StringUtils.isBlank(ipAddress)) {
            return Mono.error(new IllegalArgumentException("IP address cannot be empty"));
        }

        return findActiveTokensByIp(userId, ipAddress)
                .flatMap(docs -> revokeTokenBatch(docs, revokedBy))
                .doOnSuccess(count -> logRevocationSuccess(ipAddress, count, revokedBy))
                .doOnError(e -> logRevocationFailure(ipAddress, e, revokedBy))
                .then();
    }

    private Mono<List<QueryDocumentSnapshot>> findActiveTokensByIp(String userId, String ipAddress) {
        return Mono.fromCallable(() ->
                        firestore.collection("users")
                                .document(userId)
                                .collection(COLLECTION_REFRESH_TOKENS)
                                .whereEqualTo("ipAddress", ipAddress)
                                .whereEqualTo("revoked", false)
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .timeout(Duration.ofSeconds(5))
                .map(QuerySnapshot::getDocuments)
                .doOnNext(docs -> {
                    if (docs.isEmpty()) {
                        logger.info("No active tokens found for IP: {}", ipAddress);
                    }
                });
    }

    private Mono<Integer> revokeTokenBatch(List<QueryDocumentSnapshot> documents, String revokedBy) {
        if (documents.isEmpty()) {
            return Mono.just(0);
        }

        return Mono.fromCallable(() -> {
                    WriteBatch batch = firestore.batch();
                    documents.forEach(doc ->
                            batch.update(doc.getReference(), Map.of(
                                    "revoked", true,
                                    "revokedAt", FieldValue.serverTimestamp(),
                                    "revokedBy", revokedBy
                            ))
                    );
                    return batch.commit();
                })
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .timeout(Duration.ofSeconds(10))
                .thenReturn(documents.size());
    }

    public Mono<Boolean> isRefreshTokenRevoked(String tokenId) {
        return Mono.fromCallable(() ->
                        firestore.collection(COLLECTION_REFRESH_TOKENS)
                                .document(tokenId)
                                .get()
                )
                .flatMap(apiFuture -> Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture)))
                .timeout(Duration.ofSeconds(3))
                .map(document -> document.exists() && Boolean.TRUE.equals(document.getBoolean("revoked")))
                .onErrorResume(e -> {
                    logger.error("Failed to check token revocation status", e);
                    return Mono.just(true);
                });
    }

    public Mono<Void> revokeRefreshToken(String tokenId, String revokedBy) {
        Map<String, Object> updates = Map.of(
                "revoked", true,
                "revokedAt", FieldValue.serverTimestamp(),
                "revokedBy", revokedBy
        );

        ApiFuture<WriteResult> apiFuture = firestore.collection(COLLECTION_REFRESH_TOKENS)
                .document(tokenId)
                .update(updates);

        return Mono.fromFuture(FirestoreUtil.toCompletableFuture(apiFuture))
                .timeout(Duration.ofSeconds(5))
                .doOnSuccess(__ -> logger.info("Successfully revoked token {}", tokenId))
                .doOnError(e -> logger.error("Failed to revoke token {}", tokenId, e))
                .then();
    }

    private void logRevocationSuccess(String ipAddress, int count, String revokedBy) {
        logger.info("Revoked {} tokens for IP: {}", count, ipAddress);
        auditLogService.logSecurityEvent(
                "TOKEN_REVOCATION",
                ipAddress,
                Map.of(
                        "count", count,
                        "reason", "blacklisted_ip",
                        "initiator", revokedBy
                ).toString()
        );
    }

    private void logRevocationFailure(String ipAddress, Throwable e, String revokedBy) {
        logger.error("Failed to revoke tokens for IP {}", ipAddress, e);
        auditLogService.logSecurityEvent(
                "TOKEN_REVOCATION_FAILURE",
                ipAddress,
                Map.of(
                        "error", e.getMessage(),
                        "initiator", revokedBy
                ).toString()
        );
    }

    // Claim extraction methods
    public Mono<Claims> getClaimsFromToken(String token) {
        if (StringUtils.isBlank(token)) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Token cannot be empty"));
        }

        return parseToken(token)
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(Duration.ofSeconds(2))
                .doOnSuccess(claims -> logger.debug("Successfully extracted claims from token"))
                .doOnError(e -> logger.warn("Failed to extract claims from token: {}", e.getMessage()))
                .onErrorMap(this::mapToSecurityException);
    }

    public Mono<String> getUserIdFromToken(String token) {
        return getClaimsFromToken(token)
                .map(Claims::getSubject)
                .switchIfEmpty(Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "Missing subject claim")));
    }

    public Mono<String> getEmailFromToken(String token) {
        return getClaimsFromToken(token)
                .flatMap(claims -> {
                    String email = claims.get("email", String.class);
                    return StringUtils.isNotBlank(email)
                            ? Mono.just(email)
                            : Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "Missing email claim"));
                });
    }

    public Mono<List<String>> getRolesFromToken(String token) {
        return getClaimsFromToken(token)
                .map(claims -> {
                    List<String> roles = claims.get("roles", List.class);
                    return roles != null ? roles : Collections.emptyList();
                });
    }

    public Mono<Set<String>> getPermissionsFromToken(String token) {
        return getClaimsFromToken(token)
                .map(claims -> {
                    List<String> permissions = claims.get("permissions", List.class);
                    return permissions != null
                            ? new HashSet<>(permissions)
                            : Collections.emptySet();
                });
    }

    // Email verification token methods
    public Mono<String> generateEmailVerificationToken(String userId, String email, String ipAddress) {
        if (StringUtils.isBlank(userId)) {
            return Mono.error(new IllegalArgumentException("User ID cannot be empty"));
        }
        if (StringUtils.isBlank(email)) {
            return Mono.error(new IllegalArgumentException("Email cannot be empty"));
        }
        if (StringUtils.isBlank(ipAddress)) {
            return Mono.error(new IllegalArgumentException("IP address cannot be empty"));
        }

        return Mono.fromCallable(() -> {
                    Map<String, Object> claims = buildEmailVerificationClaims(userId, email, ipAddress);
                    return buildEmailVerificationJwt(email, claims);
                })
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(Duration.ofSeconds(2))
                .doOnSuccess(token -> logger.info("Generated email verification token for {}", email))
                .doOnError(e -> logger.error("Failed to generate email verification token", e));
    }

    private Map<String, Object> buildEmailVerificationClaims(String userId, String email, String ipAddress) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("email", email);
        claims.put("ipAddress", ipAddress);
        claims.put("type", TOKEN_TYPE_EMAIL_VERIFICATION);
        claims.put("tokenVersion", 1);
        claims.put("generatedAt", Instant.now().getEpochSecond());
        return Collections.unmodifiableMap(claims);
    }

    private String buildEmailVerificationJwt(String email, Map<String, Object> claims) {
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(jwtConfig.getEmailVerificationExpirationInSeconds());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuer(jwtConfig.getIssuer())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .signWith(jwtConfig.accessTokenSecretKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public Mono<TokenClaims> verifyEmailVerificationToken(String token) {
        if (StringUtils.isBlank(token)) {
            return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Token cannot be empty"));
        }

        return validateToken(token, TOKEN_TYPE_EMAIL_VERIFICATION)
                .flatMap(this::validateEmailVerificationClaims)
                .map(this::buildTokenClaims)
                .doOnSuccess(claims -> logger.info("Verified email token for {}", claims.email()))
                .doOnError(e -> logger.warn("Email verification failed: {}", e.getMessage()))
                .onErrorResume(e -> {
                    if (e instanceof ExpiredJwtException) {
                        return Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "Token has expired"));
                    } else if (e instanceof SignatureException) {
                        return Mono.error(new CustomException(HttpStatus.UNAUTHORIZED, "Invalid token signature"));
                    } else if (e instanceof MalformedJwtException) {
                        return Mono.error(new CustomException(HttpStatus.BAD_REQUEST, "Malformed token"));
                    } else if (e instanceof CustomException ce) {
                        return Mono.error(ce);
                    } else {
                        logger.error("Unexpected token error: {}", e.getMessage(), e);
                        return Mono.error(new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Token processing failed"));
                    }
                });
    }

    private Mono<Claims> validateEmailVerificationClaims(Claims claims) {
        return Mono.just(claims)
                .filter(c -> TOKEN_TYPE_EMAIL_VERIFICATION.equals(c.get("type")))
                .switchIfEmpty(Mono.error(new CustomException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid token type, expected email verification")))
                .filter(c -> StringUtils.isNotBlank(c.getSubject()))
                .switchIfEmpty(Mono.error(new CustomException(
                        HttpStatus.UNAUTHORIZED,
                        "Missing email in token")));
    }

    private TokenClaims buildTokenClaims(Claims claims) {
        return TokenClaims.builder()
                .userId(claims.get("userId", String.class))
                .email(claims.getSubject())
                .ipAddress(claims.get("ipAddress", String.class))
                .expiration(claims.getExpiration())
                .tokenVersion(claims.get("tokenVersion", Integer.class))
                .issuedAt(claims.getIssuedAt().toInstant())
                .build();
    }

    // Core token validation
    public Mono<Claims> validateToken(String token, String expectedType) {
        return Mono.fromCallable(() -> {
                    try {
                        Key signingKey = TOKEN_TYPE_REFRESH.equals(expectedType)
                                ? jwtConfig.refreshTokenSecretKey()
                                : jwtConfig.accessTokenSecretKey();

                        JwtParserBuilder parser = Jwts.parserBuilder()
                                .setSigningKey(signingKey)
                                .setAllowedClockSkewSeconds(30)
                                .requireIssuer(jwtConfig.getIssuer());

                        if (expectedType != null) {
                            parser.require("type", expectedType);
                        }

                        log.debug("Validating JWT (type={}, issuer={})", expectedType, jwtConfig.getIssuer());

                        Claims claims = parser.build().parseClaimsJws(token).getBody();

                        Date now = new Date();
                        Date expiration = claims.getExpiration();
                        if (expiration.before(new Date(now.getTime() - TimeUnit.MINUTES.toMillis(5)))) {
                            log.error("Token expired at {} (current time: {})", expiration, now);
                            throw new ExpiredJwtException(null, claims, "Token expired too long ago");
                        }

                        log.debug("Token valid for user: {}", claims.getSubject());
                        return claims;

                    } catch (ExpiredJwtException e) {
                        log.error("Token expired: {}", e.getMessage());
                        throw e;
                    } catch (MalformedJwtException e) {
                        log.error("Malformed JWT: {}", e.getMessage());
                        throw e;
                    } catch (SignatureException e) {
                        log.error("Signature mismatch (using key: {})",
                                TOKEN_TYPE_REFRESH.equals(expectedType) ? "refresh" : "access");
                        throw e;
                    } catch (JwtException e) {
                        log.error("General JWT error: {}", e.getMessage());
                        throw e;
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(this::mapToSecurityException);
    }

    public Mono<Boolean> isTokenValid(String token) {
        return getClaimsFromToken(token)
                .map(claims -> true)
                .onErrorResume(e -> Mono.just(false));
    }

    // Utility methods
    private String formatFullName(String firstName, String lastName) {
        return String.format("%s %s",
                        Objects.toString(firstName, ""),
                        Objects.toString(lastName, ""))
                .trim();
    }

    private boolean shouldEnforceIpValidation() {
        return environment.getProperty("security.ip-validation.enabled", Boolean.class, true);
    }

    public CustomException mapToSecurityException(Throwable e) {
        if (e instanceof ExpiredJwtException) {
            return new CustomException(HttpStatus.UNAUTHORIZED, "Token expired");
        }
        if (e instanceof JwtException) {
            return new CustomException(HttpStatus.UNAUTHORIZED, "Invalid token");
        }
        if (e instanceof TimeoutException) {
            return new CustomException(HttpStatus.REQUEST_TIMEOUT, "Token validation timeout");
        }
        return new CustomException(HttpStatus.INTERNAL_SERVER_ERROR, "Token processing failed");
    }

    // Device parsing helpers
    private String parseDeviceType(String userAgent) {
        if (userAgent.contains("Mobile")) return "mobile";
        if (userAgent.contains("Tablet")) return "tablet";
        return "desktop";
    }

    private String parseOperatingSystem(String userAgent) {
        if (userAgent.contains("Windows")) return "Windows";
        if (userAgent.contains("Mac OS")) return "MacOS";
        if (userAgent.contains("Linux")) return "Linux";
        if (userAgent.contains("Android")) return "Android";
        if (userAgent.contains("iOS")) return "iOS";
        return "Unknown";
    }
}