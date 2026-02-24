package com.techStack.authSys.integration;

import com.techStack.authSys.dto.request.ChangePasswordRequest;
import com.techStack.authSys.dto.request.LoginRequest;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.dto.request.VerifyOtpRequest;
import com.techStack.authSys.dto.response.LoginResponse;
import com.techStack.authSys.dto.response.OtpVerificationResult;
import com.techStack.authSys.integration.config.IntegrationTestConfig;
import com.techStack.authSys.models.user.User;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@Import(IntegrationTestConfig.class)
@ActiveProfiles("test")
@DisplayName("Authentication Flow Integration Tests")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthenticationFlowIntegrationTest {

    @Autowired
    private WebTestClient webClient;

    @Autowired
    private FirestoreUserRepository userRepository;

    private static final String TEST_EMAIL = "integration@test.com";
    private static final String TEST_PASSWORD = "TestPassword123!";

    @BeforeEach
    void setUp() {
        // Clean up test data
        userRepository.findByEmail(TEST_EMAIL)
                .flatMap(user -> userRepository.delete(user.getId()))
                .block();
    }

    @Test
    @Order(1)
    @DisplayName("✅ Complete authentication flow: Register → Login → Access Protected Resource")
    void shouldCompleteFullAuthenticationFlow() {
        // Step 1: Register
        UserRegistrationDTO registrationDTO = UserRegistrationDTO.builder()
                .email(TEST_EMAIL)
                .firstName("Test")
                .lastName("User")
                .phoneNumber("+254712345678")
                .build();

        webClient.post()
                .uri("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(registrationDTO)
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.success").isEqualTo(true)
                .jsonPath("$.data").exists();

        // Step 2: Login
        LoginRequest loginRequest = new LoginRequest(TEST_EMAIL, TEST_PASSWORD);

        String accessToken = webClient.post()
                .uri("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody(LoginResponse.class)
                .returnResult()
                .getResponseBody()
                .getAccessToken();

        // Step 3: Access protected resource
        webClient.get()
                .uri("/api/user/profile")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.data.email").isEqualTo(TEST_EMAIL);
    }

    @Test
    @Order(2)
    @DisplayName("✅ First-time setup flow: Initiate → Verify OTP → Complete")
    void shouldCompleteFirstTimeSetupFlow() {
        // Given: User with temporary password
        User user = createUserWithTempPassword();
        String tempToken = generateTempToken(user);

        // Step 1: Initiate
        webClient.post()
                .uri("/api/auth/first-time-setup/initiate")
                .header("Authorization", tempToken)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.data.otpSent").isEqualTo(true);

        // Step 2: Verify OTP (in real test, get OTP from test helper)
        String testOtp = "123456"; // From test OTP service

        String verificationToken = webClient.post()
                .uri("/api/auth/first-time-setup/verify-otp")
                .header("Authorization", tempToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new VerifyOtpRequest(testOtp))
                .exchange()
                .expectStatus().isOk()
                .expectBody(OtpVerificationResult.class)
                .returnResult()
                .getResponseBody()
                .getVerificationToken();

        // Step 3: Complete
        ChangePasswordRequest passwordRequest = new ChangePasswordRequest("NewPassword123!");

        webClient.post()
                .uri("/api/auth/first-time-setup/complete")
                .header("Authorization", verificationToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(passwordRequest)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.data.accessToken").exists()
                .jsonPath("$.data.refreshToken").exists();
    }

    // Helper methods...
}