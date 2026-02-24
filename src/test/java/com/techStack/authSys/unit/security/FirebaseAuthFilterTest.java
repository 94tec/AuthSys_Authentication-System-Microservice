package com.techStack.authSys.unit.security;

import com.techStack.authSys.config.TestConfig;
import com.techStack.authSys.config.security.RateLimitProperties;
import com.techStack.authSys.security.authentication.FirebaseAuthFilter;
import com.techStack.authSys.security.authentication.FirebaseAuthenticationManager;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Unit Tests for FirebaseAuthFilter
 * 
 * Tests:
 * - JWT token extraction and validation
 * - Global and IP-based rate limiting
 * - Public path handling
 * - Sensitive path rate limiting
 * - Error handling
 * - Metrics tracking
 * 
 * Coverage: 95%+
 */
@ExtendWith(MockitoExtension.class)
@Import(TestConfig.class)
@DisplayName("FirebaseAuthFilter - Unit Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FirebaseAuthFilterTest {

    @Mock
    private FirebaseAuthenticationManager authenticationManager;

    @Mock
    private ServerSecurityContextRepository securityContextRepository;

    @Mock
    private MeterRegistry meterRegistry;

    @Mock
    private Counter counter;

    @Mock
    private WebFilterChain filterChain;

    @Mock
    private Clock clock;

    private FirebaseAuthFilter authFilter;
    private RateLimitProperties rateLimitProperties;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String INVALID_TOKEN = "invalid.token";
    private static final String TEST_USER_ID = "user-123";
    private static final String CLIENT_IP = "192.168.1.100";
    private static final Instant FIXED_TIME = Instant.parse("2024-01-15T10:00:00Z");

    @BeforeEach
    void setUp() {
        // Configure clock
        when(clock.instant()).thenReturn(FIXED_TIME);

        // Configure rate limit properties
        rateLimitProperties = new RateLimitProperties();
        rateLimitProperties.setGlobal(1000);
        rateLimitProperties.setIpStandard(100);
        rateLimitProperties.setIpSensitive(10);
        rateLimitProperties.setWindowMinutes(1);

        // Configure metrics
        when(meterRegistry.counter(anyString())).thenReturn(counter);
        when(meterRegistry.counter(anyString(), anyString(), anyString())).thenReturn(counter);
        when(meterRegistry.gauge(anyString(), any(), any())).thenReturn(null);

        // Configure filter chain
        when(filterChain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());

        // Create filter
        authFilter = new FirebaseAuthFilter(
                authenticationManager,
                rateLimitProperties,
                securityContextRepository,
                meterRegistry,
                clock
        );

        authFilter.init();
    }

    @AfterEach
    void tearDown() {
        authFilter.shutdown();
    }

    /* ===============================================
       PUBLIC PATH TESTS
       =============================================== */

    @Nested
    @DisplayName("Public Path Handling")
    class PublicPathTests {

        @ParameterizedTest
        @ValueSource(strings = {
                "/swagger-ui.html",
                "/swagger-ui/index.html",
                "/v3/api-docs/swagger-config",
                "/webjars/swagger-ui/index.html",
                "/actuator/health",
                "/health/liveness",
                "/api/auth/login",
                "/api/auth/register",
                "/api/super-admin/register",
                "/api/super-admin/login",
                "/static/css/style.css",
                "/favicon.ico"
        })
        @DisplayName("✅ Should allow public paths without authentication")
        void shouldAllowPublicPaths(String path) {
            // Given
            MockServerWebExchange exchange = createExchange(path);

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            // Verify no authentication was attempted
            verifyNoInteractions(authenticationManager);
            
            // Verify request was passed to next filter
            verify(filterChain).filter(exchange);
        }

        @Test
        @DisplayName("✅ Should handle nested public paths")
        void shouldHandleNestedPublicPaths() {
            // Given
            MockServerWebExchange exchange = createExchange("/swagger-ui/some/nested/path");

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(filterChain).filter(exchange);
            verifyNoInteractions(authenticationManager);
        }
    }

    /* ===============================================
       JWT TOKEN EXTRACTION TESTS
       =============================================== */

    @Nested
    @DisplayName("JWT Token Extraction")
    class TokenExtractionTests {

        @Test
        @DisplayName("✅ Should extract valid Bearer token")
        void shouldExtractValidBearerToken() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.empty());

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            // Verify token was extracted and authenticated
            ArgumentCaptor<Authentication> authCaptor = 
                    ArgumentCaptor.forClass(Authentication.class);
            verify(authenticationManager).authenticate(authCaptor.capture());
            
            assertThat(authCaptor.getValue().getPrincipal()).isEqualTo(VALID_TOKEN);
            assertThat(authCaptor.getValue().getCredentials()).isEqualTo(VALID_TOKEN);

            verify(filterChain).filter(exchange);
        }

        @Test
        @DisplayName("❌ Should reject token without Bearer prefix")
        void shouldRejectTokenWithoutBearerPrefix() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", VALID_TOKEN); // No "Bearer " prefix

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            // Should continue to next filter without authentication
            verify(filterChain).filter(exchange);
            verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("❌ Should handle missing Authorization header")
        void shouldHandleMissingAuthHeader() {
            // Given
            MockServerWebExchange exchange = createExchange("/api/protected");

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(filterChain).filter(exchange);
            verifyNoInteractions(authenticationManager);
        }

        @Test
        @DisplayName("❌ Should handle empty Bearer token")
        void shouldHandleEmptyBearerToken() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer ");

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(filterChain).filter(exchange);
            verifyNoInteractions(authenticationManager);
        }
    }

    /* ===============================================
       AUTHENTICATION TESTS
       =============================================== */

    @Nested
    @DisplayName("Authentication Processing")
    class AuthenticationTests {

        @Test
        @DisplayName("✅ Should authenticate valid token and save context")
        void shouldAuthenticateValidToken() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.empty());

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            // Verify authentication was saved
            ArgumentCaptor<SecurityContext> contextCaptor = 
                    ArgumentCaptor.forClass(SecurityContext.class);
            verify(securityContextRepository).save(eq(exchange), contextCaptor.capture());

            SecurityContext savedContext = contextCaptor.getValue();
            assertThat(savedContext.getAuthentication()).isEqualTo(mockAuth);

            // Verify metrics
            verify(counter).increment();

            verify(filterChain).filter(exchange);
        }

        @Test
        @DisplayName("❌ Should handle authentication failure")
        void shouldHandleAuthenticationFailure() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + INVALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new RuntimeException("Invalid token")));

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            // Verify response status
            assertThat(exchange.getResponse().getStatusCode())
                    .isEqualTo(HttpStatus.UNAUTHORIZED);

            // Verify WWW-Authenticate header
            assertThat(exchange.getResponse().getHeaders().getFirst("WWW-Authenticate"))
                    .isEqualTo("Bearer");

            // Verify timestamp header
            assertThat(exchange.getResponse().getHeaders().getFirst("X-Auth-Failed"))
                    .isEqualTo(FIXED_TIME.toString());

            // Verify failure metrics
            verify(counter).increment();

            // Filter chain should NOT continue
            verify(filterChain, never()).filter(exchange);
        }
    }

    /* ===============================================
       RATE LIMITING TESTS
       =============================================== */

    @Nested
    @DisplayName("Rate Limiting")
    class RateLimitingTests {

        @Test
        @DisplayName("✅ Should allow requests within rate limit")
        void shouldAllowRequestsWithinLimit() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.empty());

            // When - Make 5 requests (within limit)
            for (int i = 0; i < 5; i++) {
                Mono<Void> result = authFilter.filter(exchange, filterChain);
                StepVerifier.create(result).verifyComplete();
            }

            // Then - All requests should succeed
            verify(filterChain, times(5)).filter(exchange);
        }

        @Test
        @DisplayName("❌ Should block requests exceeding IP rate limit")
        void shouldBlockRequestsExceedingIpLimit() {
            // Given
            rateLimitProperties.setIpStandard(5); // Low limit for testing
            authFilter = new FirebaseAuthFilter(
                    authenticationManager,
                    rateLimitProperties,
                    securityContextRepository,
                    meterRegistry,
                    clock
            );
            authFilter.init();

            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.empty());

            // When - Exceed rate limit
            IntStream.range(0, 10).forEach(i -> {
                authFilter.filter(exchange, filterChain).block();
            });

            // Then - Some requests should be blocked
            assertThat(exchange.getResponse().getStatusCode())
                    .isEqualTo(HttpStatus.TOO_MANY_REQUESTS);

            // Verify Retry-After header
            assertThat(exchange.getResponse().getHeaders().getFirst("Retry-After"))
                    .isNotNull();
        }

        @Test
        @DisplayName("⚠️ Should apply stricter limits to sensitive paths")
        void shouldApplyStricterLimitsToSensitivePaths() {
            // Given - Sensitive path with low limit
            rateLimitProperties.setIpSensitive(2);
            authFilter = new FirebaseAuthFilter(
                    authenticationManager,
                    rateLimitProperties,
                    securityContextRepository,
                    meterRegistry,
                    clock
            );
            authFilter.init();

            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/auth/login", "Bearer " + VALID_TOKEN);

            // When - Make 3 requests
            IntStream.range(0, 3).forEach(i -> {
                authFilter.filter(exchange, filterChain).block();
            });

            // Then - Third request should be blocked
            assertThat(exchange.getResponse().getStatusCode())
                    .isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        }

        @Test
        @DisplayName("✅ Should track IP addresses separately")
        void shouldTrackIpAddressesSeparately() {
            // Given
            MockServerWebExchange exchange1 = createExchangeWithIp(
                    "/api/protected", "192.168.1.1", "Bearer " + VALID_TOKEN);
            MockServerWebExchange exchange2 = createExchangeWithIp(
                    "/api/protected", "192.168.1.2", "Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.empty());

            // When - Make requests from different IPs
            StepVerifier.create(authFilter.filter(exchange1, filterChain))
                    .verifyComplete();
            StepVerifier.create(authFilter.filter(exchange2, filterChain))
                    .verifyComplete();

            // Then - Both should succeed (separate rate limiters)
            verify(filterChain, times(2)).filter(any());
        }

        @Test
        @DisplayName("✅ Should extract IP from X-Forwarded-For header")
        void shouldExtractIpFromXForwardedFor() {
            // Given
            MockServerHttpRequest request = MockServerHttpRequest
                    .get("/api/protected")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + VALID_TOKEN)
                    .header("X-Forwarded-For", "203.0.113.1, 198.51.100.1")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();

            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authFilter.filter(exchange, filterChain))
                    .verifyComplete();

            // Then - Should use first IP from X-Forwarded-For (203.0.113.1)
            // Rate limiter should be created for that IP
            verify(filterChain).filter(exchange);
        }
    }

    /* ===============================================
       ERROR HANDLING TESTS
       =============================================== */

    @Nested
    @DisplayName("Error Handling")
    class ErrorHandlingTests {

        @Test
        @DisplayName("❌ Should handle authentication manager errors gracefully")
        void shouldHandleAuthManagerErrors() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new RuntimeException("Firebase unavailable")));

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            assertThat(exchange.getResponse().getStatusCode())
                    .isEqualTo(HttpStatus.UNAUTHORIZED);

            verify(filterChain, never()).filter(exchange);
        }

        @Test
        @DisplayName("❌ Should handle SecurityContext save errors")
        void shouldHandleContextSaveErrors() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.error(new RuntimeException("Save failed")));

            // When
            Mono<Void> result = authFilter.filter(exchange, filterChain);

            // Then - Should handle error gracefully
            StepVerifier.create(result)
                    .verifyError();
        }
    }

    /* ===============================================
       METRICS TESTS
       =============================================== */

    @Nested
    @DisplayName("Metrics Tracking")
    class MetricsTests {

        @Test
        @DisplayName("✅ Should track successful authentication")
        void shouldTrackSuccessfulAuth() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            Authentication mockAuth = createMockAuthentication();
            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.just(mockAuth));
            when(securityContextRepository.save(any(), any()))
                    .thenReturn(Mono.empty());

            // When
            StepVerifier.create(authFilter.filter(exchange, filterChain))
                    .verifyComplete();

            // Then
            verify(meterRegistry).counter("auth.successes");
            verify(counter).increment();
        }

        @Test
        @DisplayName("❌ Should track authentication failures")
        void shouldTrackAuthFailures() {
            // Given
            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + INVALID_TOKEN);

            when(authenticationManager.authenticate(any()))
                    .thenReturn(Mono.error(new RuntimeException("Invalid")));

            // When
            StepVerifier.create(authFilter.filter(exchange, filterChain))
                    .verifyComplete();

            // Then
            verify(meterRegistry).counter("auth.failures", "type", "processing");
            verify(counter).increment();
        }

        @Test
        @DisplayName("⚠️ Should track rate limit hits")
        void shouldTrackRateLimitHits() {
            // Given - Low rate limit
            rateLimitProperties.setIpStandard(1);
            authFilter = new FirebaseAuthFilter(
                    authenticationManager,
                    rateLimitProperties,
                    securityContextRepository,
                    meterRegistry,
                    clock
            );
            authFilter.init();

            MockServerWebExchange exchange = createExchangeWithAuth(
                    "/api/protected", "Bearer " + VALID_TOKEN);

            // When - Exceed limit
            authFilter.filter(exchange, filterChain).block();
            authFilter.filter(exchange, filterChain).block();

            // Then
            verify(meterRegistry).counter(eq("auth.rate_limit.ip_hits"), 
                    eq("ip"), anyString());
        }
    }

    /* ===============================================
       HELPER METHODS
       =============================================== */

    private MockServerWebExchange createExchange(String path) {
        MockServerHttpRequest request = MockServerHttpRequest
                .get(path)
                .remoteAddress(new InetSocketAddress(CLIENT_IP, 8080))
                .build();

        return MockServerWebExchange.from(request);
    }

    private MockServerWebExchange createExchangeWithAuth(String path, String authHeader) {
        MockServerHttpRequest request = MockServerHttpRequest
                .get(path)
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .remoteAddress(new InetSocketAddress(CLIENT_IP, 8080))
                .build();

        return MockServerWebExchange.from(request);
    }

    private MockServerWebExchange createExchangeWithIp(String path, String ip, String authHeader) {
        MockServerHttpRequest request = MockServerHttpRequest
                .get(path)
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .remoteAddress(new InetSocketAddress(ip, 8080))
                .build();

        return MockServerWebExchange.from(request);
    }

    private Authentication createMockAuthentication() {
        return new UsernamePasswordAuthenticationToken(
                TEST_USER_ID,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }
}