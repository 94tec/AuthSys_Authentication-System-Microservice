package com.techStack.authSys.service;


import com.techStack.authSys.exception.AuthenticationException;
import com.techStack.authSys.dto.AuthResult;
import com.techStack.authSys.models.User;
import com.techStack.authSys.repository.AuthServiceController;
import com.techStack.authSys.repository.RateLimiterService;
import com.techStack.authSys.security.AccountStatusChecker;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;

import static org.mockito.Mockito.*;

class AuthServiceTest {

    @InjectMocks
    private AuthServiceImpl authService;

    @Mock
    private RateLimiterService rateLimiterService;

    @Mock
    private FirebaseServiceAuth firebaseServiceAuth;

    @Mock
    private MeterRegistry meterRegistry;

    @Mock
    private PasswordExpiryService passwordExpiryService;

    @Mock
    private AccountStatusChecker accountStatusChecker;

    @Mock
    private AuthServiceController authServiceController;

    @Mock
    private SuperAdminService superAdminLoginService;

    @Captor
    private ArgumentCaptor<String> emailCaptor;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void login_shouldReturnAuthResult_whenValidCredentials() {
        // Arrange
        String email = "test@example.com";
        String password = "password";
        String ipAddress = "127.0.0.1";
        String deviceFingerprint = "device-123";
        String userAgent = "Mozilla/5.0";
        String issuedAt = Instant.now().toString();
        String userId = "user-uid-001";

        User mockUser = User.builder()
                .id(userId)
                .email(email)
                .deviceFingerprint(deviceFingerprint)
                .userAgent(userAgent)
                .build();

        AuthResult expectedAuthResult = new AuthResult(mockUser, userId, "access-token", "refresh-token", null, null, null, null, false, 0,null);

        when(rateLimiterService.checkAuthRateLimit(ipAddress, email)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.getUserByEmail(email)).thenReturn(Mono.just(mockUser.toUserRecord()));
        when(firebaseServiceAuth.validateCredentials(email, password)).thenReturn(Mono.empty());
        when(accountStatusChecker.checkAccountStatus(email)).thenReturn(Mono.empty());
        when(passwordExpiryService.checkPasswordExpiry(any(), null)).thenReturn(Mono.empty());
        when(firebaseServiceAuth.fetchUserDetailsWithPermissions(any())).thenReturn(Mono.just(mockUser));
        when(authServiceController.generateAndPersistTokens(mockUser, issuedAt, deviceFingerprint, userAgent))
                .thenReturn(Mono.just(expectedAuthResult));

        // Act & Assert
        StepVerifier.create(superAdminLoginService.login(email, password, ipAddress, deviceFingerprint, userAgent, issuedAt, userId))
                .expectNext(expectedAuthResult)
                .verifyComplete();

        verify(firebaseServiceAuth).validateCredentials(email, password);
        verify(rateLimiterService).checkAuthRateLimit(ipAddress, emailCaptor.capture());
    }

    @Test
    void login_shouldReturnError_whenAuthFails() {
        String email = "fail@example.com";

        when(rateLimiterService.checkAuthRateLimit(any(), any())).thenReturn(Mono.empty());
        when(firebaseServiceAuth.getUserByEmail(email))
                .thenReturn(Mono.error(new AuthenticationException("User not found")));

        StepVerifier.create(superAdminLoginService.login(email, "wrong", "ip", "fingerprint", "agent", Instant.now().toString(), "id"))
                .expectError(AuthenticationException.class)
                .verify();
    }
}
