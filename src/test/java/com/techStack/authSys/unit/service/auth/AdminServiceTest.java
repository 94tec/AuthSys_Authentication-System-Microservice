package com.techStack.authSys.unit.service.auth;

import com.techStack.authSys.config.TestConfig;
import com.techStack.authSys.dto.request.UserRegistrationDTO;
import com.techStack.authSys.exception.auth.AccessDeniedException;
import com.techStack.authSys.models.user.*;
import com.techStack.authSys.repository.user.FirestoreUserRepository;
import com.techStack.authSys.service.auth.FirebaseServiceAuth;
import com.techStack.authSys.service.authorization.PermissionService;
import com.techStack.authSys.service.authorization.RoleAssignmentService;
import com.techStack.authSys.service.notification.EmailServiceInstance;
import com.techStack.authSys.service.observability.AuditLogService;
import com.techStack.authSys.service.user.AdminNotificationService;
import com.techStack.authSys.service.user.AdminService;
import com.techStack.authSys.repository.metrics.MetricsService;
import com.techStack.authSys.repository.session.SessionService;
import com.techStack.authSys.service.cache.RedisUserCacheService;
import com.google.firebase.auth.FirebaseAuth;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.Import;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive Unit Tests for AdminService
 * 
 * Tests Role-Based Access Control (RBAC):
 * - SUPER_ADMIN: 100% access
 * - ADMIN: 75% access (cannot manage admins)
 * 
 * Coverage: 95%+
 */
@ExtendWith(MockitoExtension.class)
@Import(TestConfig.class)
@DisplayName("AdminService - RBAC Unit Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AdminServiceTest {

    @Mock
    private FirestoreUserRepository userRepository;

    @Mock
    private FirebaseServiceAuth firebaseServiceAuth;

    @Mock
    private PermissionService permissionService;

    @Mock
    private RoleAssignmentService roleAssignmentService;

    @Mock
    private SessionService sessionService;

    @Mock
    private RedisUserCacheService cacheService;

    @Mock
    private EmailServiceInstance emailService;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private MetricsService metricsService;

    @Mock
    private FirebaseAuth firebaseAuth;

    @Mock
    private AdminNotificationService notificationService;

    @Mock
    private Clock clock;

    @InjectMocks
    private AdminService adminService;

    // Test Data
    private static final String SUPER_ADMIN_ID = "super-admin-123";
    private static final String ADMIN_ID = "admin-456";
    private static final String USER_ID = "user-789";
    private static final String TARGET_USER_EMAIL = "target@example.com";
    private static final String IP_ADDRESS = "192.168.1.1";
    private static final Instant FIXED_TIME = Instant.parse("2024-01-15T10:00:00Z");

    @BeforeEach
    void setUp() {
        when(clock.instant()).thenReturn(FIXED_TIME);
        when(auditLogService.logAuditEvent(anyString(), any(), anyString(), anyMap()))
                .thenReturn(Mono.empty());
    }

    /* ===============================================
       ADMIN CREATION TESTS (SUPER_ADMIN ONLY)
       =============================================== */

    @Nested
    @DisplayName("Create Admin User (100% Access)")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class CreateAdminTests {

        @Test
        @Order(1)
        @DisplayName("✅ SUPER_ADMIN should create admin successfully")
        void superAdminShouldCreateAdmin() {
            // Given
            UserRegistrationDTO userDto = createUserRegistrationDTO();
            User createdAdmin = createAdminUser();

            when(cacheService.isEmailRegistered(anyString())).thenReturn(Mono.just(false));
            when(firebaseServiceAuth.createFirebaseUser(any(), anyString(), anyString(), anyString()))
                    .thenReturn(Mono.just(createdAdmin));
            when(roleAssignmentService.assignRolesAndPermissions(any(), any()))
                    .thenReturn(Mono.just(createdAdmin));
            when(emailService.sendEmail(anyString(), anyString(), anyString()))
                    .thenReturn(Mono.empty());
            when(cacheService.cacheRegisteredEmail(anyString())).thenReturn(Mono.empty());

            // When
            Mono<User> result = adminService.createAdmin(
                    userDto, SUPER_ADMIN_ID, Roles.SUPER_ADMIN, IP_ADDRESS);

            // Then
            StepVerifier.create(result)
                    .assertNext(admin -> {
                        assertThat(admin).isNotNull();
                        assertThat(admin.getRoles()).contains(Roles.ADMIN);
                        assertThat(admin.isForcePasswordChange()).isTrue();
                        assertThat(admin.getCreatedBy()).isEqualTo(SUPER_ADMIN_ID);
                    })
                    .verifyComplete();

            // Verify email was checked
            verify(cacheService).isEmailRegistered(TARGET_USER_EMAIL);

            // Verify user was created in Firebase
            verify(firebaseServiceAuth).createFirebaseUser(
                    any(User.class), anyString(), eq(IP_ADDRESS), eq("admin-creation"));

            // Verify roles were assigned
            verify(roleAssignmentService).assignRolesAndPermissions(any(), any());

            // Verify welcome email was sent
            verify(emailService).sendEmail(
                    eq(TARGET_USER_EMAIL), contains("Admin Account Created"), anyString());

            // Verify metrics
            verify(metricsService).incrementCounter("admin.created.success");
        }

        @Test
        @Order(2)
        @DisplayName("❌ ADMIN should NOT create admin (403 Forbidden)")
        void adminShouldNotCreateAdmin() {
            // Given
            UserRegistrationDTO userDto = createUserRegistrationDTO();

            // When & Then
            StepVerifier.create(
                    adminService.createAdmin(userDto, ADMIN_ID, Roles.ADMIN, IP_ADDRESS))
                    .expectErrorMatches(e ->
                            e instanceof AccessDeniedException &&
                            e.getMessage().contains("Only SUPER_ADMIN can create admin users"))
                    .verify();

            // Verify no admin was created
            verifyNoInteractions(firebaseServiceAuth, emailService);
        }

        @Test
        @Order(3)
        @DisplayName("❌ USER should NOT create admin (403 Forbidden)")
        void userShouldNotCreateAdmin() {
            // Given
            UserRegistrationDTO userDto = createUserRegistrationDTO();

            // When & Then
            StepVerifier.create(
                    adminService.createAdmin(userDto, USER_ID, Roles.USER, IP_ADDRESS))
                    .expectErrorMatches(e ->
                            e instanceof AccessDeniedException &&
                            e.getMessage().contains("Only SUPER_ADMIN"))
                    .verify();

            verifyNoInteractions(firebaseServiceAuth);
        }

        @Test
        @Order(4)
        @DisplayName("❌ Should fail if email already exists")
        void shouldFailIfEmailExists() {
            // Given
            UserRegistrationDTO userDto = createUserRegistrationDTO();

            when(cacheService.isEmailRegistered(anyString())).thenReturn(Mono.just(true));

            // When & Then
            StepVerifier.create(
                    adminService.createAdmin(userDto, SUPER_ADMIN_ID, Roles.SUPER_ADMIN, IP_ADDRESS))
                    .expectErrorMatches(e ->
                            e instanceof IllegalStateException &&
                            e.getMessage().contains("Email already registered"))
                    .verify();

            verify(cacheService).isEmailRegistered(TARGET_USER_EMAIL);
            verifyNoInteractions(firebaseServiceAuth);
        }

        @ParameterizedTest
        @EnumSource(value = Roles.class, names = {"USER", "MANAGER", "ADMIN"})
        @DisplayName("❌ Non-SUPER_ADMIN roles should be denied")
        void nonSuperAdminRolesShouldBeDenied(Roles role) {
            // Given
            UserRegistrationDTO userDto = createUserRegistrationDTO();

            // When & Then
            StepVerifier.create(
                    adminService.createAdmin(userDto, "some-user", role, IP_ADDRESS))
                    .expectError(AccessDeniedException.class)
                    .verify();

            verifyNoInteractions(firebaseServiceAuth);
        }
    }

    /* ===============================================
       USER APPROVAL TESTS (75% & 100% Access)
       =============================================== */

    @Nested
    @DisplayName("Approve User (75%/100% Access)")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    class ApproveUserTests {

        @Test
        @Order(1)
        @DisplayName("✅ SUPER_ADMIN should approve regular user")
        void superAdminShouldApproveRegularUser() {
            // Given
            User pendingUser = createPendingUser(Set.of(Roles.USER));
            User approvedUser = createActiveUser(Set.of(Roles.USER));

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(pendingUser));
            when(permissionService.resolveEffectivePermissions(any()))
                    .thenReturn(Set.of("read:profile", "update:profile"));
            when(userRepository.saveUserWithPermissions(any(), any()))
                    .thenReturn(Mono.just(approvedUser));
            when(notificationService.notifyUserApproved(any())).thenReturn(Mono.empty());

            // When
            Mono<User> result = adminService.approveUser(
                    USER_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN);

            // Then
            StepVerifier.create(result)
                    .assertNext(user -> {
                        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
                        assertThat(user.isEnabled()).isTrue();
                        assertThat(user.getApprovedBy()).isEqualTo(SUPER_ADMIN_ID);
                    })
                    .verifyComplete();

            verify(userRepository).saveUserWithPermissions(any(), any());
            verify(notificationService).notifyUserApproved(any());
            verify(metricsService).incrementCounter("user.approved.success");
        }

        @Test
        @Order(2)
        @DisplayName("✅ ADMIN should approve regular user")
        void adminShouldApproveRegularUser() {
            // Given
            User pendingUser = createPendingUser(Set.of(Roles.USER));
            User approvedUser = createActiveUser(Set.of(Roles.USER));

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(pendingUser));
            when(permissionService.resolveEffectivePermissions(any()))
                    .thenReturn(Set.of("read:profile"));
            when(userRepository.saveUserWithPermissions(any(), any()))
                    .thenReturn(Mono.just(approvedUser));
            when(notificationService.notifyUserApproved(any())).thenReturn(Mono.empty());

            // When
            Mono<User> result = adminService.approveUser(
                    USER_ID, ADMIN_ID, Roles.ADMIN);

            // Then
            StepVerifier.create(result)
                    .assertNext(user -> {
                        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
                    })
                    .verifyComplete();

            verify(userRepository).saveUserWithPermissions(any(), any());
        }

        @Test
        @Order(3)
        @DisplayName("✅ SUPER_ADMIN should approve admin user")
        void superAdminShouldApproveAdminUser() {
            // Given
            User pendingAdmin = createPendingUser(Set.of(Roles.ADMIN));
            User approvedAdmin = createActiveUser(Set.of(Roles.ADMIN));

            when(userRepository.findById(ADMIN_ID)).thenReturn(Mono.just(pendingAdmin));
            when(permissionService.resolveEffectivePermissions(any()))
                    .thenReturn(Set.of("manage:users", "view:analytics"));
            when(userRepository.saveUserWithPermissions(any(), any()))
                    .thenReturn(Mono.just(approvedAdmin));
            when(notificationService.notifyUserApproved(any())).thenReturn(Mono.empty());

            // When
            Mono<User> result = adminService.approveUser(
                    ADMIN_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN);

            // Then
            StepVerifier.create(result)
                    .assertNext(user -> {
                        assertThat(user.getRoles()).contains(Roles.ADMIN);
                        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
                    })
                    .verifyComplete();
        }

        @Test
        @Order(4)
        @DisplayName("❌ ADMIN should NOT approve admin user (403 Forbidden)")
        void adminShouldNotApproveAdminUser() {
            // Given
            User pendingAdmin = createPendingUser(Set.of(Roles.ADMIN));

            when(userRepository.findById(ADMIN_ID)).thenReturn(Mono.just(pendingAdmin));

            // When & Then
            StepVerifier.create(
                    adminService.approveUser(ADMIN_ID, ADMIN_ID, Roles.ADMIN))
                    .expectErrorMatches(e ->
                            e instanceof AccessDeniedException &&
                            e.getMessage().contains("cannot approve user with higher privileges"))
                    .verify();

            verify(userRepository, never()).saveUserWithPermissions(any(), any());
        }

        @Test
        @Order(5)
        @DisplayName("❌ Should fail if user not in PENDING status")
        void shouldFailIfUserNotPending() {
            // Given
            User activeUser = createActiveUser(Set.of(Roles.USER));

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(activeUser));

            // When & Then
            StepVerifier.create(
                    adminService.approveUser(USER_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN))
                    .expectErrorMatches(e ->
                            e instanceof IllegalStateException &&
                            e.getMessage().contains("not pending approval"))
                    .verify();
        }

        @ParameterizedTest
        @MethodSource("provideApprovalAuthorizationScenarios")
        @DisplayName("🔄 Authorization matrix for approval")
        void shouldEnforceAuthorizationMatrix(
                Roles performerRole,
                Set<Roles> targetUserRoles,
                boolean shouldSucceed) {
            
            // Given
            User targetUser = createPendingUser(targetUserRoles);

            when(userRepository.findById(anyString())).thenReturn(Mono.just(targetUser));

            if (shouldSucceed) {
                when(permissionService.resolveEffectivePermissions(any()))
                        .thenReturn(Set.of("permission1"));
                when(userRepository.saveUserWithPermissions(any(), any()))
                        .thenReturn(Mono.just(targetUser));
                when(notificationService.notifyUserApproved(any())).thenReturn(Mono.empty());
            }

            // When
            Mono<User> result = adminService.approveUser(
                    "target-user", "performer", performerRole);

            // Then
            if (shouldSucceed) {
                StepVerifier.create(result)
                        .expectNextCount(1)
                        .verifyComplete();
            } else {
                StepVerifier.create(result)
                        .expectError(AccessDeniedException.class)
                        .verify();
            }
        }

        private static Stream<Arguments> provideApprovalAuthorizationScenarios() {
            return Stream.of(
                    // SUPER_ADMIN can approve anyone
                    Arguments.of(Roles.SUPER_ADMIN, Set.of(Roles.USER), true),
                    Arguments.of(Roles.SUPER_ADMIN, Set.of(Roles.MANAGER), true),
                    Arguments.of(Roles.SUPER_ADMIN, Set.of(Roles.ADMIN), true),
                    Arguments.of(Roles.SUPER_ADMIN, Set.of(Roles.SUPER_ADMIN), true),

                    // ADMIN can approve regular users only
                    Arguments.of(Roles.ADMIN, Set.of(Roles.USER), true),
                    Arguments.of(Roles.ADMIN, Set.of(Roles.MANAGER), true),
                    Arguments.of(Roles.ADMIN, Set.of(Roles.ADMIN), false),
                    Arguments.of(Roles.ADMIN, Set.of(Roles.SUPER_ADMIN), false),

                    // USER cannot approve anyone
                    Arguments.of(Roles.USER, Set.of(Roles.USER), false)
            );
        }
    }

    /* ===============================================
       USER REJECTION TESTS (75% & 100% Access)
       =============================================== */

    @Nested
    @DisplayName("Reject User (75%/100% Access)")
    class RejectUserTests {

        @Test
        @DisplayName("✅ SUPER_ADMIN should reject regular user")
        void superAdminShouldRejectRegularUser() {
            // Given
            User pendingUser = createPendingUser(Set.of(Roles.USER));
            String reason = "Incomplete documents";

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(pendingUser));
            when(notificationService.notifyUserRejected(any(), anyString())).thenReturn(Mono.empty());
            when(userRepository.delete(USER_ID)).thenReturn(Mono.empty());

            // When
            Mono<Void> result = adminService.rejectUser(
                    USER_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN, reason);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(notificationService).notifyUserRejected(any(), eq(reason));
            verify(userRepository).delete(USER_ID);
            verify(metricsService).incrementCounter("user.rejected.success");
        }

        @Test
        @DisplayName("✅ ADMIN should reject regular user")
        void adminShouldRejectRegularUser() {
            // Given
            User pendingUser = createPendingUser(Set.of(Roles.USER));
            String reason = "Policy violation";

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(pendingUser));
            when(notificationService.notifyUserRejected(any(), anyString())).thenReturn(Mono.empty());
            when(userRepository.delete(USER_ID)).thenReturn(Mono.empty());

            // When
            Mono<Void> result = adminService.rejectUser(
                    USER_ID, ADMIN_ID, Roles.ADMIN, reason);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(userRepository).delete(USER_ID);
        }

        @Test
        @DisplayName("❌ ADMIN should NOT reject admin user")
        void adminShouldNotRejectAdminUser() {
            // Given
            User pendingAdmin = createPendingUser(Set.of(Roles.ADMIN));
            String reason = "Some reason";

            when(userRepository.findById(ADMIN_ID)).thenReturn(Mono.just(pendingAdmin));

            // When & Then
            StepVerifier.create(
                    adminService.rejectUser(ADMIN_ID, ADMIN_ID, Roles.ADMIN, reason))
                    .expectError(AccessDeniedException.class)
                    .verify();

            verify(userRepository, never()).delete(anyString());
        }
    }

    /* ===============================================
       SUSPEND USER TESTS (75% & 100% Access)
       =============================================== */

    @Nested
    @DisplayName("Suspend User (75%/100% Access)")
    class SuspendUserTests {

        @Test
        @DisplayName("✅ SUPER_ADMIN should suspend regular user")
        void superAdminShouldSuspendRegularUser() {
            // Given
            User activeUser = createActiveUser(Set.of(Roles.USER));
            String reason = "Suspicious activity";

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(activeUser));
            when(userRepository.update(any(User.class))).thenReturn(Mono.just(activeUser));
            when(sessionService.invalidateAllSessionsForUser(USER_ID)).thenReturn(Mono.empty());

            // When
            Mono<Void> result = adminService.suspendUser(
                    USER_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN, reason);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).update(userCaptor.capture());
            
            User suspendedUser = userCaptor.getValue();
            assertThat(suspendedUser.getStatus()).isEqualTo(UserStatus.SUSPENDED);
            assertThat(suspendedUser.isEnabled()).isFalse();

            verify(sessionService).invalidateAllSessionsForUser(USER_ID);
            verify(metricsService).incrementCounter("user.suspended.success");
        }

        @Test
        @DisplayName("✅ ADMIN should suspend regular user")
        void adminShouldSuspendRegularUser() {
            // Given
            User activeUser = createActiveUser(Set.of(Roles.USER));
            String reason = "Policy violation";

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(activeUser));
            when(userRepository.update(any(User.class))).thenReturn(Mono.just(activeUser));
            when(sessionService.invalidateAllSessionsForUser(USER_ID)).thenReturn(Mono.empty());

            // When
            Mono<Void> result = adminService.suspendUser(
                    USER_ID, ADMIN_ID, Roles.ADMIN, reason);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(sessionService).invalidateAllSessionsForUser(USER_ID);
        }

        @Test
        @DisplayName("✅ SUPER_ADMIN should suspend admin user")
        void superAdminShouldSuspendAdminUser() {
            // Given
            User adminUser = createActiveUser(Set.of(Roles.ADMIN));
            String reason = "Investigation pending";

            when(userRepository.findById(ADMIN_ID)).thenReturn(Mono.just(adminUser));
            when(userRepository.update(any(User.class))).thenReturn(Mono.just(adminUser));
            when(sessionService.invalidateAllSessionsForUser(ADMIN_ID)).thenReturn(Mono.empty());

            // When
            Mono<Void> result = adminService.suspendUser(
                    ADMIN_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN, reason);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            verify(userRepository).update(any(User.class));
            verify(sessionService).invalidateAllSessionsForUser(ADMIN_ID);
        }

        @Test
        @DisplayName("❌ ADMIN should NOT suspend admin user")
        void adminShouldNotSuspendAdminUser() {
            // Given
            User adminUser = createActiveUser(Set.of(Roles.ADMIN));
            String reason = "Some reason";

            when(userRepository.findById(ADMIN_ID)).thenReturn(Mono.just(adminUser));

            // When & Then
            StepVerifier.create(
                    adminService.suspendUser(ADMIN_ID, ADMIN_ID, Roles.ADMIN, reason))
                    .expectError(AccessDeniedException.class)
                    .verify();

            verify(userRepository, never()).update(any());
            verify(sessionService, never()).invalidateAllSessionsForUser(anyString());
        }
    }

    /* ===============================================
       REACTIVATE USER TESTS
       =============================================== */

    @Nested
    @DisplayName("Reactivate User (75%/100% Access)")
    class ReactivateUserTests {

        @Test
        @DisplayName("✅ SUPER_ADMIN should reactivate suspended user")
        void superAdminShouldReactivateSuspendedUser() {
            // Given
            User suspendedUser = createSuspendedUser(Set.of(Roles.USER));

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(suspendedUser));
            when(userRepository.update(any(User.class))).thenReturn(Mono.just(suspendedUser));

            // When
            Mono<Void> result = adminService.reactivateUser(
                    USER_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).update(userCaptor.capture());
            
            User reactivatedUser = userCaptor.getValue();
            assertThat(reactivatedUser.getStatus()).isEqualTo(UserStatus.ACTIVE);
            assertThat(reactivatedUser.isEnabled()).isTrue();

            verify(metricsService).incrementCounter("user.reactivated.success");
        }

        @Test
        @DisplayName("❌ Should fail if user not suspended")
        void shouldFailIfUserNotSuspended() {
            // Given
            User activeUser = createActiveUser(Set.of(Roles.USER));

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(activeUser));

            // When & Then
            StepVerifier.create(
                    adminService.reactivateUser(USER_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN))
                    .expectErrorMatches(e ->
                            e instanceof IllegalStateException &&
                            e.getMessage().contains("not suspended"))
                    .verify();
        }
    }

    /* ===============================================
       FORCE PASSWORD RESET TESTS
       =============================================== */

    @Nested
    @DisplayName("Force Password Reset (75%/100% Access)")
    class ForcePasswordResetTests {

        @Test
        @DisplayName("✅ SUPER_ADMIN should force password reset")
        void superAdminShouldForcePasswordReset() {
            // Given
            User user = createActiveUser(Set.of(Roles.USER));

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(user));
            when(userRepository.update(any(User.class))).thenReturn(Mono.just(user));
            when(sessionService.invalidateAllSessionsForUser(USER_ID)).thenReturn(Mono.empty());

            // When
            Mono<Void> result = adminService.forcePasswordReset(
                    USER_ID, SUPER_ADMIN_ID, Roles.SUPER_ADMIN);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).update(userCaptor.capture());
            
            User updatedUser = userCaptor.getValue();
            assertThat(updatedUser.isForcePasswordChange()).isTrue();

            verify(sessionService).invalidateAllSessionsForUser(USER_ID);
        }

        @Test
        @DisplayName("✅ ADMIN should force password reset for regular user")
        void adminShouldForcePasswordReset() {
            // Given
            User user = createActiveUser(Set.of(Roles.USER));

            when(userRepository.findById(USER_ID)).thenReturn(Mono.just(user));
            when(userRepository.update(any(User.class))).thenReturn(Mono.just(user));
            when(sessionService.invalidateAllSessionsForUser(USER_ID)).thenReturn(Mono.empty());

            // When
            Mono<Void> result = adminService.forcePasswordReset(
                    USER_ID, ADMIN_ID, Roles.ADMIN);

            // Then
            StepVerifier.create(result)
                    .verifyComplete();
        }

        @Test
        @DisplayName("❌ ADMIN should NOT force password reset for admin")
        void adminShouldNotForcePasswordResetForAdmin() {
            // Given
            User adminUser = createActiveUser(Set.of(Roles.ADMIN));

            when(userRepository.findById(ADMIN_ID)).thenReturn(Mono.just(adminUser));

            // When & Then
            StepVerifier.create(
                    adminService.forcePasswordReset(ADMIN_ID, ADMIN_ID, Roles.ADMIN))
                    .expectError(AccessDeniedException.class)
                    .verify();

            verify(userRepository, never()).update(any());
        }
    }

    /* ===============================================
       QUERY USERS TESTS
       =============================================== */

    @Nested
    @DisplayName("Query Users (Role-Filtered)")
    class QueryUsersTests {

        @Test
        @DisplayName("✅ SUPER_ADMIN should see all users")
        void superAdminShouldSeeAllUsers() {
            // Given
            User regularUser = createActiveUser(Set.of(Roles.USER));
            User adminUser = createActiveUser(Set.of(Roles.ADMIN));

            AdminService.UserQueryFilters filters = new AdminService.UserQueryFilters(
                    UserStatus.ACTIVE, null, null, null);

            when(userRepository.findByStatus(UserStatus.ACTIVE))
                    .thenReturn(Flux.just(regularUser, adminUser));

            // When
            Flux<User> result = adminService.findUsers(Roles.SUPER_ADMIN, filters);

            // Then
            StepVerifier.create(result)
                    .expectNext(regularUser)
                    .expectNext(adminUser)
                    .verifyComplete();
        }

        @Test
        @DisplayName("✅ ADMIN should see regular users only")
        void adminShouldSeeRegularUsersOnly() {
            // Given
            User regularUser = createActiveUser(Set.of(Roles.USER));
            User adminUser = createActiveUser(Set.of(Roles.ADMIN));

            AdminService.UserQueryFilters filters = new AdminService.UserQueryFilters(
                    UserStatus.ACTIVE, null, null, null);

            when(userRepository.findByStatus(UserStatus.ACTIVE))
                    .thenReturn(Flux.just(regularUser, adminUser));

            // When
            Flux<User> result = adminService.findUsers(Roles.ADMIN, filters);

            // Then - Should only see regular user, not admin
            StepVerifier.create(result)
                    .expectNext(regularUser)
                    .verifyComplete();
        }
    }

    /* ===============================================
       STATISTICS TESTS
       =============================================== */

    @Nested
    @DisplayName("Get Statistics (Role-Filtered)")
    class StatisticsTests {

        @Test
        @DisplayName("✅ SUPER_ADMIN should get all statistics")
        void superAdminShouldGetAllStatistics() {
            // Given
            User regularUser = createActiveUser(Set.of(Roles.USER));
            User adminUser = createActiveUser(Set.of(Roles.ADMIN));

            when(userRepository.findByStatus(UserStatus.ACTIVE))
                    .thenReturn(Flux.just(regularUser, adminUser));
            when(userRepository.findByStatus(UserStatus.PENDING_APPROVAL))
                    .thenReturn(Flux.empty());
            when(userRepository.findByStatus(UserStatus.SUSPENDED))
                    .thenReturn(Flux.empty());
            when(userRepository.findByStatus(UserStatus.REJECTED))
                    .thenReturn(Flux.empty());

            // When
            Mono<Map<String, Long>> result = adminService.getUserStatistics(Roles.SUPER_ADMIN);

            // Then
            StepVerifier.create(result)
                    .assertNext(stats -> {
                        assertThat(stats.get("active")).isEqualTo(2L); // Both users
                        assertThat(stats.get("total")).isEqualTo(2L);
                    })
                    .verifyComplete();
        }

        @Test
        @DisplayName("✅ ADMIN should get filtered statistics")
        void adminShouldGetFilteredStatistics() {
            // Given
            User regularUser = createActiveUser(Set.of(Roles.USER));
            User adminUser = createActiveUser(Set.of(Roles.ADMIN));

            when(userRepository.findByStatus(UserStatus.ACTIVE))
                    .thenReturn(Flux.just(regularUser, adminUser));
            when(userRepository.findByStatus(UserStatus.PENDING_APPROVAL))
                    .thenReturn(Flux.empty());
            when(userRepository.findByStatus(UserStatus.SUSPENDED))
                    .thenReturn(Flux.empty());
            when(userRepository.findByStatus(UserStatus.REJECTED))
                    .thenReturn(Flux.empty());

            // When
            Mono<Map<String, Long>> result = adminService.getUserStatistics(Roles.ADMIN);

            // Then - Should only count regular user
            StepVerifier.create(result)
                    .assertNext(stats -> {
                        assertThat(stats.get("active")).isEqualTo(1L); // Only regular user
                        assertThat(stats.get("total")).isEqualTo(1L);
                    })
                    .verifyComplete();
        }
    }

    /* ===============================================
       HELPER METHODS
       =============================================== */

    private UserRegistrationDTO createUserRegistrationDTO() {
        return UserRegistrationDTO.builder()
                .email(TARGET_USER_EMAIL)
                .firstName("New")
                .lastName("Admin")
                .phoneNumber("+254712345678")
                .department("Engineering")
                .build();
    }

    private User createAdminUser() {
        User user = new User();
        user.setId("new-admin-123");
        user.setEmail(TARGET_USER_EMAIL);
        user.setRoles(Set.of(Roles.ADMIN));
        user.setForcePasswordChange(true);
        user.setCreatedBy(SUPER_ADMIN_ID);
        user.setCreatedAt(FIXED_TIME);
        return user;
    }

    private User createPendingUser(Set<Roles> roles) {
        User user = new User();
        user.setId("pending-user-123");
        user.setEmail("pending@example.com");
        user.setRoles(roles);
        user.setStatus(UserStatus.PENDING_APPROVAL);
        user.setEnabled(false);
        return user;
    }

    private User createActiveUser(Set<Roles> roles) {
        User user = new User();
        user.setId("active-user-123");
        user.setEmail("active@example.com");
        user.setRoles(roles);
        user.setStatus(UserStatus.ACTIVE);
        user.setEnabled(true);
        return user;
    }

    private User createSuspendedUser(Set<Roles> roles) {
        User user = new User();
        user.setId("suspended-user-123");
        user.setEmail("suspended@example.com");
        user.setRoles(roles);
        user.setStatus(UserStatus.SUSPENDED);
        user.setEnabled(false);
        return user;
    }
}