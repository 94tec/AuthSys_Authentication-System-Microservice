package com.techStack.authSys.config.observability;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI/Swagger Configuration
 *
 * Configures interactive API documentation with JWT authentication support.
 * Access at: http://localhost:{port}/swagger-ui.html
 *
 * Features:
 * - Interactive API testing
 * - JWT Bearer authentication
 * - Request/response examples
 * - Multi-environment support
 * - Organized by functional tags
 */
@Configuration
public class OpenAPIConfiguration {

    @Value("${server.port:8080}")
    private int serverPort;

    @Value("${spring.application.name:AuthSys}")
    private String applicationName;

    @Bean
    public OpenAPI defineOpenApi() {
        return new OpenAPI()
                .info(buildApiInfo())
                .servers(buildServers())
                .security(buildSecurityRequirements())
                .components(buildComponents())
                .tags(buildTags());
    }

    /* =========================
       API Information
       ========================= */

    private Info buildApiInfo() {
        Contact contact = new Contact()
                .name("TechStack AuthSys Team")
                .email("support@techstack.com")
                .url("https://github.com/techstack/authsys");

        License license = new License()
                .name("MIT License")
                .url("https://opensource.org/licenses/MIT");

        return new Info()
                .title(applicationName + " - Authentication & Authorization API")
                .version("2.0.0")
                .description(buildDescription())
                .contact(contact)
                .license(license);
    }

    /* =========================
       API Description
       ========================= */

    private String buildDescription() {
        return """
                # Authentication & Authorization Microservice
                
                Enterprise-grade authentication system with multi-factor authentication,
                role-based access control, and comprehensive security features.
                
                ---
                
                ## 🎯 Features
                
                - 🔐 **JWT Authentication** — Secure token-based auth
                - 📱 **2FA via OTP** — SMS-based two-factor authentication
                - 🔑 **First-Time Setup** — Forced password change for new users
                - 👥 **RBAC** — Role-based access control with hierarchy
                - 🛡️ **Rate Limiting** — Protection against abuse
                - 📊 **Audit Logging** — Complete activity trail
                - 🔄 **Password Reset** — Secure password recovery
                - 🚨 **Security Events** — Real-time alerts and monitoring
                
                ---
                
                ## 🚀 Quick Start Guide
                
                ### For Regular Users
                
                **1. Register** (if registration is open)
                ```
                POST /api/auth/register
                {
                  "email": "user@example.com",
                  "password": "SecurePass123!@",
                  "phoneNumber": "+254712345678"
                }
                ```
                
                **2. Login**
                ```
                POST /api/auth/login
                {
                  "email": "user@example.com",
                  "password": "SecurePass123!@"
                }
                ```
                
                **3. Verify Login OTP** (if 2FA enabled)
                ```
                POST /api/auth/login-otp/verify
                Headers: Authorization: Bearer <temporary-token>
                {
                  "otp": "123456"
                }
                ```
                
                **4. Authorize Swagger**
                - Click the 🔓 **Authorize** button above
                - Enter: `Bearer <your-access-token>`
                - Click **Authorize** and **Close**
                - All requests will now include your token automatically
                
                ---
                
                ### For Super Admin (First-Time Login)
                
                **1. Login with Temporary Password**
                ```
                POST /api/auth/login
                {
                  "email": "admin@techstack.com",
                  "password": "<temporary-password-from-email>"
                }
                ```
                Response: `temporaryToken` + `firstTimeLogin: true`
                
                **2. Change Password**
                ```
                POST /api/auth/first-time-setup/change-password
                Headers: Authorization: Bearer <temporary-token>
                {
                  "newPassword": "NewSecurePass123!@",
                  "confirmPassword": "NewSecurePass123!@"
                }
                ```
                OTP sent to phone.
                
                **3. Verify OTP**
                ```
                POST /api/auth/first-time-setup/verify-otp
                Headers: Authorization: Bearer <temporary-token>
                {
                  "otp": "123456"
                }
                ```
                Response: Full access tokens.
                
                ---
                
                ## 👤 Roles Hierarchy
                
                ```
                SUPER_ADMIN (all permissions)
                    ↓
                ADMIN (user management, approvals)
                    ↓
                MANAGER (team management)
                    ↓
                USER (basic access)
                ```
                
                Each role inherits permissions from roles below it.
                
                ---
                
                ## 🔐 Authentication Types
                
                | Type | When Used | Token Scope | Validity |
                |------|-----------|-------------|----------|
                | **Access Token** | Normal API access | Full access | 15 min |
                | **Refresh Token** | Renew access token | Token refresh only | 7 days |
                | **Temporary Token (Setup)** | First-time password change | FIRST_TIME_SETUP | 30 min |
                | **Temporary Token (Login)** | Login OTP verification | LOGIN_OTP | 5 min |
                
                ---
                
                ## 📱 OTP System
                
                **Two OTP Types:**
                
                ### Setup OTP (First-Time)
                - Validity: 10 minutes
                - Max attempts: 3
                - Rate limit: 5 requests / 15 minutes
                - Used for: Initial password change
                
                ### Login OTP (2FA)
                - Validity: 5 minutes
                - Max attempts: 3
                - Rate limit: 10 requests / 15 minutes
                - Used for: Every login authentication
                
                ---
                
                ## ⚠️ Rate Limits
                
                - **Global**: 1000 requests/minute
                - **Per IP**: 100 requests/minute
                - **Login**: 10 attempts/15 minutes
                - **Setup OTP**: 5 requests/15 minutes
                - **Login OTP**: 10 requests/15 minutes
                - **Password Reset**: 3 requests/hour
                
                ---
                
                ## 📞 Support
                
                - **Email**: support@techstack.com
                - **Documentation**: https://docs.techstack.com
                - **GitHub**: https://github.com/techstack/authsys
                - **Status Page**: https://status.techstack.com
                
                ---
                
                ## 🔧 Development Mode
                
                When `sms.provider.enabled=false`:
                - OTP codes logged to console
                - No actual SMS sent
                - Perfect for testing
                
                Check application logs for OTP codes in development.
                """;
    }

    /* =========================
       Server Configurations
       ========================= */

    private List<Server> buildServers() {
        Server localServer = new Server()
                .url("http://localhost:" + serverPort)
                .description("🔧 Local Development Server");

        Server devServer = new Server()
                .url("https://dev-api.techstack.com")
                .description("🚧 Development Environment");

        Server stagingServer = new Server()
                .url("https://staging-api.techstack.com")
                .description("🧪 Staging Environment");

        Server prodServer = new Server()
                .url("https://api.techstack.com")
                .description("🚀 Production Environment");

        return List.of(localServer, devServer, stagingServer, prodServer);
    }

    /* =========================
       Security Requirements
       ========================= */

    private List<SecurityRequirement> buildSecurityRequirements() {
        return List.of(
                new SecurityRequirement().addList("Bearer Authentication")
        );
    }

    /* =========================
       Security Components
       ========================= */

    private Components buildComponents() {
        SecurityScheme jwtScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .in(SecurityScheme.In.HEADER)
                .name("Authorization")
                .description("""
                        **JWT Authentication**
                        
                        Enter your JWT token in the format: `Bearer <token>`
                        
                        **How to get a token:**
                        
                        1. **Register** (if needed):
                           POST /api/auth/register
                        
                        2. **Login**:
                           POST /api/auth/login
                        
                        3. **Verify OTP** (if 2FA enabled):
                           POST /api/auth/login-otp/verify
                        
                        4. **Copy the `accessToken`** from response
                        
                        5. **Click 'Authorize' button** above
                        
                        6. **Enter**: `Bearer <your-access-token>`
                        
                        7. **Click 'Authorize'** and close the dialog
                        
                        **Your token will be automatically added to all requests!**
                        
                        ---
                        
                        **Token Types:**
                        - Access Token: Full API access (15 min)
                        - Temporary Token: Limited scope (5-30 min)
                        """);

        SecurityScheme apiKeyScheme = new SecurityScheme()
                .type(SecurityScheme.Type.APIKEY)
                .in(SecurityScheme.In.HEADER)
                .name("X-API-Key")
                .description("""
                        **API Key Authentication** (Optional)
                        
                        For service-to-service authentication.
                        
                        Contact support@techstack.com to obtain an API key.
                        """);

        return new Components()
                .addSecuritySchemes("Bearer Authentication", jwtScheme)
                .addSecuritySchemes("API Key", apiKeyScheme);
    }

    /* =========================
       API Endpoint Tags
       ========================= */

    private List<Tag> buildTags() {
        return List.of(
                new Tag()
                        .name("Authentication")
                        .description("""
                                User authentication with multi-factor support.
                                
                                **Endpoints:**
                                - Login (email + password)
                                - Logout
                                - Token refresh
                                
                                **Features:**
                                - JWT tokens
                                - 2FA via OTP
                                - Rate limiting
                                """),

                new Tag()
                        .name("First-Time Setup")
                        .description("""
                                Password change and OTP verification for new users.
                                
                                **Flow:**
                                1. Login with temporary password
                                2. Change password (OTP sent)
                                3. Verify OTP
                                4. Get full access
                                
                                **Security:**
                                - Forced password change
                                - Phone verification
                                - Temporary tokens (30 min)
                                """),

                new Tag()
                        .name("Login OTP")
                        .description("""
                                Two-factor authentication for login (2FA).
                                
                                **When Required:**
                                - User has verified phone
                                - 2FA enabled in config
                                
                                **Flow:**
                                1. Login with password
                                2. Verify OTP sent to phone
                                3. Get full access
                                
                                **Security:**
                                - OTP valid 5 minutes
                                - Max 3 attempts
                                - Rate limited
                                """),

                new Tag()
                        .name("Super Admin")
                        .description("""
                                Super administrator operations and bootstrap.
                                
                                **Features:**
                                - Bootstrap initial admin
                                - System configuration
                                - Full user management
                                - Audit log access
                                
                                **Access:** SUPER_ADMIN role only
                                """),

                new Tag()
                        .name("User Management")
                        .description("""
                                User CRUD operations and approval workflows.
                                
                                **Features:**
                                - Create/update/delete users
                                - Approve pending users
                                - Lock/unlock accounts
                                - View user activity
                                
                                **Access:** ADMIN+ roles
                                """),

                new Tag()
                        .name("Password Management")
                        .description("""
                                Password reset, change, and recovery.
                                
                                **Features:**
                                - Self-service password change
                                - Forgot password flow
                                - Password reset via email
                                - Password strength validation
                                
                                **Security:**
                                - Rate limited
                                - Secure reset tokens
                                - Email verification
                                """),

                new Tag()
                        .name("OTP")
                        .description("""
                                One-time password generation and verification.
                                
                                **Types:**
                                - Setup OTP (10 min, first-time)
                                - Login OTP (5 min, 2FA)
                                
                                **Features:**
                                - SMS delivery
                                - Rate limiting
                                - Attempt tracking
                                - Resend capability
                                """),

                new Tag()
                        .name("Roles & Permissions")
                        .description("""
                                Role assignment and permission management.
                                
                                **Hierarchy:**
                                SUPER_ADMIN > ADMIN > MANAGER > USER
                                
                                **Features:**
                                - Assign/revoke roles
                                - Custom permissions
                                - Role inheritance
                                
                                **Access:** ADMIN+ roles
                                """),

                new Tag()
                        .name("Audit Logs")
                        .description("""
                                System audit trail and activity monitoring.
                                
                                **Logged Events:**
                                - Authentication attempts
                                - User changes
                                - Role assignments
                                - Security events
                                
                                **Features:**
                                - Time-based filtering
                                - User activity search
                                - Export capabilities
                                
                                **Access:** ADMIN+ roles
                                """),

                new Tag()
                        .name("Health")
                        .description("""
                                System health checks and monitoring.
                                
                                **Endpoints:**
                                - Health status
                                - Readiness probe
                                - Liveness probe
                                - Metrics
                                
                                **Access:** Public (no auth)
                                """)
        );
    }
}