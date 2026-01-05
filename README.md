# AuthSys - Enterprise Authentication & Authorization Microservice

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.0-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**AuthSys** is a production-ready, reactive authentication and authorization microservice built with **Spring Boot 3.2.0** and **Java 21**. It provides enterprise-grade security features including user management, role-based access control (RBAC), session handling, OTP verification, and comprehensive audit logging.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture Overview](#-architecture-overview)
- [Technology Stack](#-technology-stack)
- [Getting Started](#-getting-started)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)
- [Security Features](#-security-features)
- [Monitoring & Observability](#-monitoring--observability)
- [Development](#-development)
- [Deployment](#-deployment)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Features

### Core Authentication & Authorization
- **Reactive Architecture**: Built on Spring WebFlux for high-performance, non-blocking operations
- **Role-Based Access Control (RBAC)**: Hierarchical role system (Super Admin → Admin → Manager → User)
- **Permission Management**: Granular permission system with dynamic permission resolution
- **Multi-Factor Authentication**: OTP-based verification via email and SMS
- **Session Management**: Redis-backed session store with automatic expiration

### Security & Compliance
- **AES-256 Encryption**: For sensitive data at rest
- **Password Policy Enforcement**:
    - Complexity requirements (length, special characters, numbers)
    - Password history tracking (prevents reuse)
    - Configurable expiration policies
    - Forced password changes on first login
- **Account Security**:
    - Account lockout after failed login attempts
    - IP-based rate limiting (global and per-endpoint)
    - Device fingerprinting and verification
    - Suspicious activity detection and blocking
- **Audit Trail**: Comprehensive logging of all authentication events

### User Management
- **User Registration Workflow**:
    - Email/phone validation
    - Duplicate detection with Redis caching
    - Role assignment with approval workflows
    - Email verification with secure tokens
- **User Approval System**:
    - Hierarchical approval levels based on requested roles
    - Manager/Admin approval for sensitive roles
    - Rejection with reason tracking
    - Account restoration capabilities
- **Account Lifecycle**:
    - Pending → Active → Suspended → Rejected states
    - Automatic cleanup of incomplete registrations
    - Session invalidation on account changes

### Bootstrap & Initialization
- **Transactional Super Admin Creation**:
    - Atomic operations with automatic rollback on failure
    - Distributed lock mechanism for multi-instance safety
    - Idempotent operations (safe to run multiple times)
    - Emergency password recovery via secure logging
- **Monitoring Dashboard**: Health checks and metrics for bootstrap operations

### Integration & Communication
- **Firebase Integration**:
    - Firebase Authentication for user identity
    - Cloud Firestore for scalable NoSQL storage
    - Real-time data synchronization
- **Redis Caching**: High-performance caching for:
    - User sessions
    - Registered emails
    - Rate limiting buckets
    - Permission cache
- **Notification Services**:
    - Email notifications via Brevo API
    - SMS notifications for OTP
    - Welcome emails and verification workflows

### Key Architectural Patterns

1. **Reactive Programming**: Non-blocking I/O using Project Reactor
2. **Orchestration Pattern**: Coordinated workflows for complex operations
3. **Transaction Management**: Atomic operations with automatic rollback
4. **Circuit Breaker**: Graceful degradation for external service failures
5. **Event-Driven**: Application events for cross-cutting concerns
6. **Repository Pattern**: Abstraction over Firebase and Redis data access

---

## 💻 Technology Stack

| Category | Technology | Version | Purpose |
|----------|------------|---------|---------|
| **Runtime** | Java | 21.0.8 | Primary language |
| **Framework** | Spring Boot | 3.2.0 | Application framework |
| **Web Server** | Spring WebFlux | 3.2.0 | Reactive web server (Netty) |
| **Database** | Cloud Firestore | Latest | NoSQL document database |
| **Cache** | Redis | 7.x | Session store & caching |
| **Authentication** | Firebase Auth | 9.2.0 | User identity management |
| **Security** | Spring Security | 6.2.0 | Security framework |
| **Rate Limiting** | Bucket4j | 8.x | Token bucket algorithm |
| **Messaging** | Brevo API | Latest | Email/SMS notifications |
| **Monitoring** | Micrometer | 1.12.0 | Metrics collection |
| **Build Tool** | Maven | 3.x | Dependency management |

## 🚀 Getting Started

### Prerequisites

Before running AuthSys, ensure you have:

- **Java 21** JDK installed ([Download](https://adoptium.net/))
- **Maven 3.8+** for building ([Download](https://maven.apache.org/download.cgi))
- **Redis Server** running locally or remotely
- **Firebase Project** with service account credentials
- **Brevo API Key** (optional, for email/SMS)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/authsys.git
   cd authsys
   ```

2. **Configure Firebase**
    - Download service account JSON from Firebase Console
    - Place it in `src/main/resources/firebase-service-account.json`
    - Or set `GOOGLE_APPLICATION_CREDENTIALS` environment variable

3. **Configure application properties**
   ```bash
   cp src/main/resources/application.properties.example \
      src/main/resources/application.properties
   ```
   Edit the file with your configuration (see [Configuration](#-configuration))

4. **Build the project**
   ```bash
   mvn clean install -DskipTests
   ```

5. **Run the application**
   ```bash
   java -jar target/authSys-0.0.1-SNAPSHOT.jar
   ```

   Or using Maven:
   ```bash
   mvn spring-boot:run
   ```

The application will start on **http://localhost:8001**

### Quick Start with Docker

```bash
# Build the image
docker build -t authsys:latest .

# Run with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f authsys
```

### Verifying Installation

1. **Health Check**
   ```bash
   curl http://localhost:8001/actuator/health
   ```

2. **Bootstrap Status**
   ```bash
   curl http://localhost:8001/actuator/bootstrap-health
   ```

3. **Super Admin Login** (after bootstrap completes)
   ```bash
   curl -X POST http://localhost:8001/api/super-admin/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "your-super-admin@example.com",
       "password": "your-password"
     }'
   ```

---

## ⚙️ Configuration

### Application Properties

Create `application.properties` in `src/main/resources`:

```properties
# Server Configuration
server.port=8001
spring.application.name=authSys

# Firebase Configuration
firebase.project-id=your-project-id
firebase.api-key=your-firebase-api-key

# Redis Configuration
spring.data.redis.host=localhost
spring.data.redis.port=6379
spring.data.redis.password=
spring.data.redis.database=0
spring.data.redis.timeout=60000

# Security Configuration
security.rate-limit.global=1000
security.rate-limit.ip-standard=100
security.rate-limit.ip-sensitive=10
security.rate-limit.window-minutes=1

# Password Policy
security.password.min-length=8
security.password.require-uppercase=true
security.password.require-lowercase=true
security.password.require-digit=true
security.password.require-special=true
security.password.expiry-days=90
security.password.history-count=5

# Session Configuration
session.timeout-minutes=30
session.max-concurrent=3

# Super Admin Bootstrap
app.super-admin.email=admin@example.com
app.super-admin.phone=+254700000000

# Email Configuration (Brevo)
brevo.api-key=your-brevo-api-key
brevo.sender.email=noreply@yourdomain.com
brevo.sender.name=AuthSys

# Application URLs
app.base-url=http://localhost:8001
app.frontend-url=http://localhost:3000

# Monitoring
management.endpoints.web.exposure.include=health,metrics
management.endpoint.health.show-details=when-authorized
```

### Environment Variables

For production deployments, use environment variables:

```bash
export FIREBASE_PROJECT_ID=your-project-id
export FIREBASE_API_KEY=your-firebase-api-key
export REDIS_HOST=redis.example.com
export REDIS_PASSWORD=your-redis-password
export BREVO_API_KEY=your-brevo-api-key
export SUPER_ADMIN_EMAIL=admin@example.com
export SUPER_ADMIN_PHONE=+254700000000
```

### Firebase Service Account

Place your Firebase service account JSON in one of these locations:

1. `src/main/resources/firebase-service-account.json`
2. Path specified by `GOOGLE_APPLICATION_CREDENTIALS` environment variable
3. Default application credentials (GCP environments)

---

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+254700000000",
  "roles": ["USER"],
  "username": "johndoe",
  "identityNo": "12345678"
}
```

**Response: 201 Created**
```json
{
  "id": "user-uuid",
  "email": "user@example.com",
  "status": "PENDING_APPROVAL",
  "roles": ["USER"],
  "message": "Registration successful. Awaiting approval."
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response: 200 OK**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "refresh-token-uuid",
  "expiresIn": 3600,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "roles": ["USER"],
    "permissions": ["READ_OWN_PROFILE", "UPDATE_OWN_PROFILE"]
  }
}
```

#### Verify Email
```http
GET /api/auth/verify-email?token=verification-token-here
```

**Response: 200 OK**
```json
{
  "message": "Email verified successfully",
  "emailVerified": true
}
```

### User Management Endpoints

#### Approve User (Admin/Manager)
```http
POST /api/admin/users/{userId}/approve
Authorization: Bearer {admin-token}
Content-Type: application/json

{
  "approvedBy": "admin-user-id"
}
```

#### Reject User (Admin/Manager)
```http
POST /api/admin/users/{userId}/reject
Authorization: Bearer {admin-token}
Content-Type: application/json

{
  "rejectedBy": "admin-user-id",
  "reason": "Invalid credentials provided"
}
```

#### List Pending Users
```http
GET /api/admin/users/pending
Authorization: Bearer {admin-token}
```

**Response: 200 OK**
```json
{
  "users": [
    {
      "id": "user-uuid",
      "email": "pending@example.com",
      "firstName": "Jane",
      "lastName": "Smith",
      "roles": ["MANAGER"],
      "status": "PENDING_APPROVAL",
      "canApprove": true,
      "approvalLevel": "ADMIN_OR_SUPER_ADMIN",
      "createdAt": "2025-01-05T10:30:00Z"
    }
  ],
  "total": 1
}
```

### Super Admin Endpoints

#### Create Super Admin (Bootstrap)
```http
POST /api/super-admin/register
Content-Type: application/json

{
  "email": "superadmin@example.com",
  "password": "VerySecure123!",
  "phoneNumber": "+254700000000"
}
```

#### Super Admin Login
```http
POST /api/super-admin/login
Content-Type: application/json

{
  "email": "superadmin@example.com",
  "password": "VerySecure123!"
}
```

### Session Management

#### Invalidate Session
```http
POST /api/auth/logout
Authorization: Bearer {token}
```

#### Get Active Sessions
```http
GET /api/users/sessions
Authorization: Bearer {token}
```

---

## 🔒 Security Features

### Password Policy

AuthSys enforces a comprehensive password policy:

- **Minimum length**: 8 characters (configurable)
- **Complexity requirements**:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
- **Password history**: Prevents reuse of last 5 passwords
- **Expiration**: Passwords expire after 90 days (configurable)
- **Common password blocking**: Prevents use of commonly compromised passwords

### Rate Limiting

Three-tier rate limiting strategy:

1. **Global Rate Limit**: 1000 requests/minute across all IPs
2. **Standard Endpoints**: 100 requests/minute per IP
3. **Sensitive Endpoints**: 10 requests/minute per IP (login, register, password reset)

Rate limit headers in responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704456000
```

### Account Security

- **Account Lockout**: After 5 failed login attempts
- **Lockout Duration**: 30 minutes (configurable)
- **Session Timeout**: 30 minutes of inactivity
- **Max Concurrent Sessions**: 3 per user (configurable)
- **Device Tracking**: Fingerprinting for suspicious device detection
- **IP Whitelisting/Blacklisting**: Support for restricted access

### Audit Logging

All security events are logged:

- User registration attempts
- Login successes and failures
- Password changes
- Role/permission changes
- Account status changes (suspension, activation)
- Session creation and termination
- Admin actions (approvals, rejections)

Audit logs include:
- Timestamp
- User ID
- Action type
- IP address
- Device fingerprint
- Result (success/failure)
- Additional metadata

---

## 📊 Monitoring & Observability

### Actuator Endpoints

AuthSys exposes Spring Boot Actuator endpoints for monitoring:

```bash
# Health Check
GET /actuator/health

# Metrics
GET /actuator/metrics

# Bootstrap Health (Custom)
GET /actuator/bootstrap-health
```

### Key Metrics

The system tracks the following metrics (available via `/actuator/metrics`):

#### Authentication Metrics
- `auth.login.success` - Successful logins
- `auth.login.failure` - Failed login attempts
- `auth.rate_limit.hits` - Rate limit violations
- `auth.session.created` - New sessions created
- `auth.session.expired` - Expired sessions

#### Registration Metrics
- `user.registration.success` - Successful registrations
- `user.registration.failure` - Failed registrations
- `user.approval.pending` - Users awaiting approval
- `user.approval.approved` - Users approved
- `user.approval.rejected` - Users rejected

#### Bootstrap Metrics
- `bootstrap.super_admin.created` - Super admin creations
- `bootstrap.super_admin.already_exists` - Skipped bootstraps
- `bootstrap.super_admin.failed` - Failed bootstrap attempts
- `bootstrap.creation.time` - Bootstrap duration

#### System Metrics
- `auth.rate_limit.ips` - Number of tracked IPs
- `redis.operations.success` - Successful Redis operations
- `redis.operations.failure` - Failed Redis operations
- `firebase.operations.success` - Successful Firebase operations
- `firebase.operations.failure` - Failed Firebase operations

### Health Checks

Custom health indicators:

```json
{
  "status": "UP",
  "components": {
    "bootstrap": {
      "status": "UP",
      "details": {
        "isComplete": true,
        "criticalFailures": 0,
        "recentRollbacks": 0,
        "lastAttempt": "2025-01-05T10:00:00Z"
      }
    },
    "redis": {
      "status": "UP",
      "details": {
        "version": "7.0.0"
      }
    },
    "firestore": {
      "status": "UP"
    }
  }
}
```

### Logging

Structured logging with correlation IDs:

```
2025-01-05 10:30:15.123 INFO  [authSys] [user-registration] [req-abc123] 
  Registration attempt for email: u***r@example.com from IP: 192.168.1.100
  
2025-01-05 10:30:15.456 INFO  [authSys] [user-creation] [req-abc123]
  ✅ Full registration chain complete for user: u***r@example.com
  
2025-01-05 10:30:16.789 INFO  [authSys] [email-verification] [req-abc123]
  ✅ Sent verification email to u***r@example.com
```
### Code Style

This project follows [Google Java Style Guide](https://google.github.io/styleguide/javaguide.html).

To format code:
```bash
mvn formatter:format
```

### Debugging

Enable debug logging:
```properties
logging.level.com.techStack.authSys=DEBUG
logging.level.org.springframework.security=DEBUG
```

---

## 🚢 Deployment

### Production Checklist

Before deploying to production:

- [ ] Update `application.properties` with production values
- [ ] Configure Firebase production project
- [ ] Set up Redis cluster or managed Redis service
- [ ] Configure SSL/TLS certificates
- [ ] Set up monitoring and alerting
- [ ] Enable audit logging
- [ ] Configure backup strategy for Firestore
- [ ] Review and adjust rate limits
- [ ] Set strong passwords for super admin
- [ ] Configure CORS policies
- [ ] Set up CI/CD pipeline
- [ ] Perform security audit
- [ ] Load test the application

### Docker Deployment

```bash
# Build production image
docker build -t authsys:1.0.0 -f docker/Dockerfile .

# Run container
docker run -d \
  --name authsys \
  -p 8001:8001 \
  -e SPRING_PROFILES_ACTIVE=prod \
  -e FIREBASE_PROJECT_ID=${FIREBASE_PROJECT_ID} \
  -e REDIS_HOST=${REDIS_HOST} \
  -e REDIS_PASSWORD=${REDIS_PASSWORD} \
  authsys:1.0.0
```

### Kubernetes Deployment

Example deployment manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authsys
spec:
  replicas: 3
  selector:
    matchLabels:
      app: authsys
  template:
    metadata:
      labels:
        app: authsys
    spec:
      containers:
      - name: authsys
        image: authsys:1.0.0
        ports:
        - containerPort: 8001
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "prod"
        - name: REDIS_HOST
          valueFrom:
            secretKeyRef:
              name: authsys-secrets
              key: redis-host
        livenessProbe:
          httpGet:
            path: /actuator/health
            port: 8001
          initialDelaySeconds: 60
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 5
```

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes** with clear commit messages
4. **Add tests** for new functionality
5. **Ensure tests pass** (`mvn test`)
6. **Submit a pull request**

### Code Review Process

All pull requests require:
- [ ] Passing CI/CD pipeline
- [ ] Code review from at least one maintainer
- [ ] Test coverage ≥ 80%
- [ ] Updated documentation
- [ ] No security vulnerabilities (Snyk scan)

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📧 Support & Contact

**Maintainer:** Fixtone Kaloki  
**Email:** fixtone94tec@gmail.com  
**GitHub:** [@94tec](https://github.com/94tec)

For bugs and feature requests, please [create an issue](https://github.com/your-org/authsys/issues).

For security vulnerabilities, please email fixtone94tec@gmail.com directly.

---

## 🙏 Acknowledgments

- Spring Framework team for excellent reactive support
- Firebase team for robust authentication services
- Redis community for high-performance caching
- All contributors who have helped improve this project

---

## 📚 Additional Resources

- [Spring Boot Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Firebase Documentation](https://firebase.google.com/docs)
- [Redis Documentation](https://redis.io/docs/)
- [Project Reactor](https://projectreactor.io/docs)

---

**Built with ❤️ using Spring Boot and Java 21**