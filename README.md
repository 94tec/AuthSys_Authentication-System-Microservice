# AuthSys - Enterprise Authentication & Authorization Microservice

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.java.net/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.0-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

> **Production-ready, reactive authentication microservice** built with Spring WebFlux, Firebase, and Redis. Designed for high-performance, scalability, and enterprise-grade security.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Technology Stack](#-technology-stack)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)
- [Security](#-security)
- [Monitoring](#-monitoring)
- [Deployment](#-deployment)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**AuthSys** is an enterprise-grade authentication and authorization microservice that provides:

- **Reactive Architecture**: Built on Spring WebFlux for non-blocking, high-throughput operations
- **Firebase Integration**: Leverages Firebase Auth as the source of identity truth
- **Hybrid Data Strategy**: Redis for performance, Firestore for durability
- **Advanced Security**: Multi-layered security with rate limiting, encryption, and risk-based authentication
- **Production Ready**: Comprehensive monitoring, audit logging, and failure handling

### Why AuthSys?

- ✅ **Zero Blocking Calls**: Fully reactive with Project Reactor
- ✅ **Horizontally Scalable**: Stateless design ready for Kubernetes
- ✅ **Security First**: OWASP best practices, STRIDE threat modeling
- ✅ **Observable**: Prometheus metrics, OpenTelemetry tracing, structured audit logs
- ✅ **Resilient**: Circuit breakers, retry logic, graceful degradation

---

## 🚀 Key Features

### Core Authentication & Authorization

#### 🔐 Authentication Flows
- **User Registration**: Idempotent registration with email/phone verification
- **Risk-Scored Login**: Dynamic MFA triggers based on real-time risk assessment
- **Token Management**: Dual-token system (access + refresh) with rotation and reuse detection
- **Session Control**: Redis-backed sessions with concurrent session limits

#### 👥 Role-Based Access Control (RBAC)
- **Hierarchical Roles**: Super Admin → Admin → Manager → User
- **Permission Inheritance**: Roles inherit permissions from lower-privilege roles
- **Dynamic Resolution**: Real-time permission calculation with caching

#### 🎯 Attribute-Based Access Control (ABAC)
- **Policy Engine**: SpEL-based condition evaluation
- **Context-Aware**: Decisions based on user, resource, time, IP, and custom attributes
- **Flexible Rules**: YAML-based policy configuration

### Security & Compliance

#### 🛡️ Multi-Layered Security
```
Layer 1: Rate Limiting (5-1000 req/min by endpoint)
Layer 2: Input Validation (XSS, injection prevention)
Layer 3: Authentication (Firebase + Custom JWT)
Layer 4: Authorization (RBAC + ABAC)
Layer 5: Encryption (AES-256-GCM for sensitive data)
```

#### 🔒 Password Security
- **Complexity Enforcement**: Length, uppercase, lowercase, numbers, special chars
- **Password History**: Prevents reuse of last 5 passwords
- **Expiry Policy**: Configurable password expiration (default: 90 days)
- **Temporary Passwords**: Encrypted, one-time use, mandatory rotation

#### 🚨 Threat Detection
- **Risk Scoring**: IP reputation, device fingerprinting, velocity analysis, geolocation
- **Account Lockout**: Exponential backoff after failed login attempts
- **Token Abuse Detection**: Refresh token reuse detection with family revocation
- **Suspicious Activity**: Real-time anomaly detection

### User Management

#### 📝 Registration Workflow
```
Request → Rate Check → Duplicate Check → Firebase User Creation
  → Firestore Profile → Role Assignment → Firebase Custom Claims
  → Verification Tokens → Email/SMS Notifications → Audit Log
```

#### ✅ Approval System
- **Hierarchical Approvals**: Role-based approval requirements
- **Workflow States**: Pending → Active | Rejected | Suspended
- **Rejection Tracking**: Reasons and audit trail
- **Account Restoration**: Reactivation with approval

### Integration & Services

#### 🔥 Firebase Integration
- **Identity Management**: Firebase Auth as SSoT for user identity
- **Cloud Firestore**: Scalable NoSQL for profiles, sessions, audit logs
- **Custom Claims**: Role and permission sync to Firebase tokens

#### ⚡ Redis Caching
```
Sessions:      session:access:{id}, session:refresh:{token}
Rate Limits:   rate:{endpoint}:{ip}
User Cache:    user:profile:{uid}, user:permissions:{uid}
OTP:           otp:activation:{uid}, otp:attempts:{uid}
Blacklist:     blacklist:token:{jti}
```

#### 📧 Notification Services
- **Email**: Brevo API for verification, welcome, password reset
- **SMS**: Africa's Talking for OTP delivery
- **Templates**: Customizable HTML email templates

### Monitoring & Observability

#### 📊 Metrics (Prometheus)
- Authentication: success/failure rates, risk scores
- Performance: Firebase latency, Redis hit rates
- Security: rate limit violations, failed attempts
- Business: registrations, approvals, active sessions

#### 🔍 Distributed Tracing
- **OpenTelemetry**: Full request tracing across services
- **Correlation IDs**: Request tracking through all layers
- **Span Details**: Service calls, database operations, external APIs

#### 📝 Audit Logging
- **Comprehensive Events**: All security-relevant actions logged
- **Structured Format**: JSON logs with full context
- **Firestore Storage**: Immutable audit trail
- **Real-time Alerts**: Event-driven notifications for critical actions

---

## 🏗️ Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                      API Gateway / Load Balancer             │
│                   (Rate Limiting, IP Filtering)              │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
┌─────────▼─────┐ ┌──────▼──────┐ ┌─────▼────────┐
│ AuthSys Pod 1 │ │ AuthSys 2   │ │ AuthSys 3    │
│ (Spring Boot) │ │             │ │              │
└─────────┬─────┘ └──────┬──────┘ └─────┬────────┘
          │               │               │
          └───────────────┼───────────────┘
                          │
          ┌───────────────┼───────────────────┐
          │               │                   │
┌─────────▼─────┐ ┌──────▼──────┐ ┌─────────▼────────┐
│   Firebase    │ │  Firestore  │ │  Redis Cluster   │
│     Auth      │ │  (Durable)  │ │  (Performance)   │
└───────────────┘ └─────────────┘ └──────────────────┘
```

### Request Flow

```
Client Request
    ↓
API Gateway (Rate Limit)
    ↓
WebFlux Filter Chain
    ↓
┌─────────────────────────────────┐
│ 1. Token Validation             │
│    - Extract JWT                │
│    - Verify signature           │
│    - Check blacklist            │
└─────────────┬───────────────────┘
              ↓
┌─────────────────────────────────┐
│ 2. User Context Loading         │
│    - Redis cache lookup         │
│    - Firestore fallback         │
│    - Permission resolution      │
└─────────────┬───────────────────┘
              ↓
┌─────────────────────────────────┐
│ 3. Authorization Check          │
│    - RBAC evaluation            │
│    - ABAC policy execution      │
│    - Decision (Allow/Deny)      │
└─────────────┬───────────────────┘
              ↓
┌─────────────────────────────────┐
│ 4. Business Logic               │
│    - Service execution          │
│    - Reactive operations        │
└─────────────┬───────────────────┘
              ↓
┌─────────────────────────────────┐
│ 5. Audit & Metrics              │
│    - Log event                  │
│    - Update metrics             │
└─────────────────────────────────┘
```

### Data Flow Strategy

| Operation | Redis (Cache) | Firestore (Durable) | Strategy |
|-----------|---------------|---------------------|----------|
| Session Read | ✅ Primary | ✅ Fallback | Cache-aside |
| Session Write | ✅ Async | ✅ Sync | Write-through |
| User Profile | ✅ TTL 1hr | ✅ Source | Cache-aside |
| Permissions | ✅ TTL 15min | ✅ Source | Cache-aside |
| Audit Logs | ❌ | ✅ Only | Write-only |
| Rate Limits | ✅ Only | ❌ | Cache-only |

---

## 💻 Technology Stack

| Category | Technology | Version | Purpose |
|----------|-----------|---------|---------|
| **Runtime** | Java | 21.0.8 | Primary language with virtual threads |
| **Framework** | Spring Boot | 3.2.0 | Application framework |
| **Web** | Spring WebFlux | 3.2.0 | Reactive web server (Netty) |
| **Reactive** | Project Reactor | 3.6.x | Non-blocking I/O |
| **Security** | Spring Security | 6.2.0 | Security framework |
| **Database** | Cloud Firestore | Latest | NoSQL document database |
| **Cache** | Redis | 7.x | Session store & caching |
| **Cache Client** | Lettuce | 6.3.x | Reactive Redis client |
| **Auth Provider** | Firebase Auth | 9.2.0 | Identity management |
| **JWT** | Nimbus JOSE+JWT | 9.37.3 | Token generation/validation |
| **Rate Limiting** | Bucket4j | 8.x | Token bucket algorithm |
| **Email/SMS** | Brevo API | Latest | Notification services |
| **Metrics** | Micrometer | 1.12.0 | Metrics collection |
| **Tracing** | OpenTelemetry | 1.32.0 | Distributed tracing |
| **Monitoring** | Prometheus | Latest | Metrics aggregation |
| **Resilience** | Resilience4j | 2.1.0 | Circuit breaker, retry |
| **Build** | Maven | 3.9.x | Dependency management |
| **Testing** | JUnit 5 | 5.10.x | Unit testing |
| **Testing** | Reactor Test | 3.6.x | Reactive testing |
| **Container** | Docker | 24.x | Containerization |
| **Orchestration** | Kubernetes | 1.28+ | Container orchestration |

---

## 🚀 Quick Start

### Prerequisites

Ensure you have the following installed:

- ☑️ **Java 21 JDK** - [Download](https://adoptium.net/)
- ☑️ **Maven 3.8+** - [Download](https://maven.apache.org/download.cgi)
- ☑️ **Redis 7.x** - [Installation Guide](https://redis.io/docs/getting-started/)
- ☑️ **Firebase Project** - [Create Project](https://console.firebase.google.com/)
- ☑️ **Brevo API Key** (Optional) - [Sign Up](https://www.brevo.com/)

### Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/your-org/authsys.git
cd authsys
```

#### 2. Configure Firebase

**Download Firebase Service Account:**
1. Go to Firebase Console → Project Settings → Service Accounts
2. Click "Generate New Private Key"
3. Save as `src/main/resources/firebase-service-account.json`

**Or use environment variable:**
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/firebase-service-account.json
```

#### 3. Configure Application

Create `application.properties`:

```bash
cp src/main/resources/application.properties.example \
   src/main/resources/application.properties
```

**Minimal configuration:**

```properties
# Server
server.port=8001

# Firebase
firebase.project-id=your-firebase-project-id
firebase.api-key=your-firebase-api-key

# Redis
spring.data.redis.host=localhost
spring.data.redis.port=6379

# Super Admin Bootstrap
app.super-admin.email=admin@example.com
app.super-admin.phone=+254700000000
```

#### 4. Build the Project

```bash
mvn clean install -DskipTests
```

#### 5. Run the Application

**Using Maven:**
```bash
mvn spring-boot:run
```

**Using Java:**
```bash
java -jar target/authSys-0.0.1-SNAPSHOT.jar
```

**Expected output:**
```
  ___         _   _     ___            
 / _ \  _   _| |_| |__ / __|_   _ ___ 
| |_| || | | |  _| '_ \\___ | | | / __|
|  _  || |_| | |_| | | |__) | |_| \__ \
|_| |_| \__,_|\__|_| |_|____/ \__, |___/
                              |___/     

:: Spring Boot ::                (v3.2.0)

2025-01-08 10:30:15.123 INFO  [main] AuthSysApplication: Starting AuthSysApplication
2025-01-08 10:30:17.456 INFO  [main] Netty started on port 8001
2025-01-08 10:30:17.789 INFO  [main] AuthSysApplication: Started AuthSysApplication in 2.666 seconds
```

#### 6. Verify Installation

**Health Check:**
```bash
curl http://localhost:8001/actuator/health
```

**Expected response:**
```json
{
  "status": "UP",
  "components": {
    "diskSpace": {"status": "UP"},
    "ping": {"status": "UP"},
    "redis": {"status": "UP"},
    "firestore": {"status": "UP"}
  }
}
```

**Bootstrap Status:**
```bash
curl http://localhost:8001/actuator/bootstrap-health
```

### Quick Start with Docker

#### Build and Run

```bash
# Build image
docker build -t authsys:latest .

# Run container
docker run -d \
  --name authsys \
  -p 8001:8001 \
  -e FIREBASE_PROJECT_ID=your-project-id \
  -e REDIS_HOST=host.docker.internal \
  authsys:latest

# Check logs
docker logs -f authsys
```

#### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  authsys:
    build: .
    ports:
      - "8001:8001"
    environment:
      - SPRING_PROFILES_ACTIVE=production
      - REDIS_HOST=redis
      - FIREBASE_PROJECT_ID=${FIREBASE_PROJECT_ID}
    depends_on:
      - redis
    networks:
      - authsys-network

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass ${REDIS_PASSWORD}
    networks:
      - authsys-network
    volumes:
      - redis-data:/data

networks:
  authsys-network:
    driver: bridge

volumes:
  redis-data:
```

---

## ⚙️ Configuration

### Application Properties

**Complete configuration template:**

```properties
# ============================================
# SERVER CONFIGURATION
# ============================================
server.port=8001
spring.application.name=authSys
server.shutdown=graceful

# ============================================
# FIREBASE CONFIGURATION
# ============================================
firebase.project-id=${FIREBASE_PROJECT_ID:your-project-id}
firebase.api-key=${FIREBASE_API_KEY:your-api-key}
firebase.credentials-path=${FIREBASE_CREDENTIALS_PATH:firebase-service-account.json}

# ============================================
# REDIS CONFIGURATION
# ============================================
spring.data.redis.host=${REDIS_HOST:localhost}
spring.data.redis.port=${REDIS_PORT:6379}
spring.data.redis.password=${REDIS_PASSWORD:}
spring.data.redis.database=0
spring.data.redis.timeout=60000

# Redis Connection Pool
spring.data.redis.lettuce.pool.max-active=20
spring.data.redis.lettuce.pool.max-idle=10
spring.data.redis.lettuce.pool.min-idle=5
spring.data.redis.lettuce.shutdown-timeout=100ms

# ============================================
# SECURITY CONFIGURATION
# ============================================

# JWT Configuration
auth.jwt.access-token-ttl=900
auth.jwt.refresh-token-ttl=604800
auth.jwt.key-rotation-days=30

# Rate Limiting
security.rate-limit.enabled=true
security.rate-limit.global=1000
security.rate-limit.ip-standard=100
security.rate-limit.ip-sensitive=10
security.rate-limit.window-minutes=1

# Password Policy
security.password.min-length=12
security.password.require-uppercase=true
security.password.require-lowercase=true
security.password.require-digit=true
security.password.require-special=true
security.password.expiry-days=90
security.password.history-count=5

# Account Security
security.account.max-failed-attempts=5
security.account.lockout-duration-minutes=30

# ============================================
# SESSION CONFIGURATION
# ============================================
session.timeout-minutes=30
session.max-concurrent=3
session.refresh-token-rotation=true

# ============================================
# SUPER ADMIN BOOTSTRAP
# ============================================
app.super-admin.email=${SUPER_ADMIN_EMAIL:admin@example.com}
app.super-admin.phone=${SUPER_ADMIN_PHONE:+254700000000}
app.super-admin.auto-create=${SUPER_ADMIN_AUTO_CREATE:true}

# ============================================
# NOTIFICATION SERVICES
# ============================================

# Brevo (Email/SMS)
brevo.api-key=${BREVO_API_KEY:your-brevo-api-key}
brevo.sender.email=${BREVO_SENDER_EMAIL:noreply@yourdomain.com}
brevo.sender.name=${BREVO_SENDER_NAME:AuthSys}

# Africa's Talking (SMS)
africastalking.username=${AT_USERNAME:sandbox}
africastalking.api-key=${AT_API_KEY:your-api-key}

# ============================================
# APPLICATION URLS
# ============================================
app.base-url=${APP_BASE_URL:http://localhost:8001}
app.frontend-url=${APP_FRONTEND_URL:http://localhost:3000}

# ============================================
# MONITORING & OBSERVABILITY
# ============================================

# Actuator Endpoints
management.endpoints.web.exposure.include=health,metrics,prometheus,info
management.endpoint.health.show-details=when-authorized
management.endpoint.health.probes.enabled=true

# Metrics
management.metrics.export.prometheus.enabled=true
management.metrics.tags.application=${spring.application.name}
management.metrics.tags.environment=${SPRING_PROFILES_ACTIVE:dev}

# Tracing
management.tracing.sampling.probability=1.0
management.otlp.tracing.endpoint=${OTLP_ENDPOINT:http://localhost:4318/v1/traces}

# ============================================
# LOGGING
# ============================================
logging.level.root=INFO
logging.level.com.techStack.authSys=DEBUG
logging.level.org.springframework.security=DEBUG
logging.pattern.console=%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n
logging.file.name=/app/logs/authsys.log
logging.file.max-size=100MB
logging.file.max-history=30

# ============================================
# CORS CONFIGURATION
# ============================================
auth.security.cors.allowed-origins=https://yourdomain.com,http://localhost:3000
auth.security.cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
auth.security.cors.allowed-headers=*
auth.security.cors.max-age=3600
```

### Environment Variables (Production)

For production deployments, use environment variables:

```bash
# Firebase
export FIREBASE_PROJECT_ID=production-project-id
export FIREBASE_API_KEY=production-api-key
export GOOGLE_APPLICATION_CREDENTIALS=/etc/secrets/firebase-creds.json

# Redis
export REDIS_HOST=redis.production.internal
export REDIS_PORT=6379
export REDIS_PASSWORD=strong-redis-password

# Security
export ENCRYPTION_KEY=base64-encoded-32-byte-key
export JWT_PRIVATE_KEY=base64-encoded-rsa-private-key
export JWT_PUBLIC_KEY=base64-encoded-rsa-public-key

# Super Admin
export SUPER_ADMIN_EMAIL=admin@production.com
export SUPER_ADMIN_PHONE=+254700000000

# Notifications
export BREVO_API_KEY=production-brevo-key
export AT_API_KEY=production-africastalking-key

# Monitoring
export OTLP_ENDPOINT=http://otel-collector:4318/v1/traces
```

### Permissions Configuration (YAML)

**permissions.yaml:**

```yaml
roles:
  SUPER_ADMIN:
    permissions:
      - "*:*"
    priority: 100
    description: "Full system access"
    
  ADMIN:
    inherits: [MANAGER, USER]
    permissions:
      - "read:*"
      - "write:*"
      - "delete:users"
      - "manage:roles"
      - "approve:all"
    priority: 50
    
  MANAGER:
    inherits: [USER]
    permissions:
      - "read:team_data"
      - "write:team_data"
      - "approve:user_requests"
      - "manage:team_members"
    attributes:
      max_approval_amount: 10000
    priority: 30
    
  USER:
    permissions:
      - "read:own_profile"
      - "write:own_profile"
      - "read:public_documents"
      - "create:requests"
    priority: 10

policies:
  resource_ownership:
    - name: "Owner full access"
      effect: ALLOW
      conditions:
        - "resource.ownerId == user.id"
        
  department_access:
    - name: "Department read access"
      effect: ALLOW
      conditions:
        - "resource.department == user.department"
        - "action == 'read'"
        
  business_hours:
    - name: "After hours restriction"
      effect: DENY
      conditions:
        - "time.hour >= 22 || time.hour <= 6"
        - "user.role != 'ADMIN'"
        - "user.role != 'SUPER_ADMIN'"
```

---

## 📚 API Documentation

### Base URL

```
Development: http://localhost:8001/api
Production:  https://api.yourdomain.com/api
```

### Authentication Endpoints

#### Register User

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!@#",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+254712345678",
  "username": "johndoe",
  "identityNo": "12345678",
  "roles": ["USER"]
}
```

**Response: 201 Created**
```json
{
  "id": "firebase-uid-here",
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "status": "PENDING_VERIFICATION",
  "roles": ["USER"],
  "message": "Registration successful. Please verify your email.",
  "verificationRequired": true
}
```

**Error Responses:**
```json
// 400 Bad Request - Validation Error
{
  "status": 400,
  "error": "BAD_REQUEST",
  "message": "Password must be at least 12 characters",
  "timestamp": "2025-01-08T10:30:00Z"
}

// 409 Conflict - Duplicate User
{
  "status": 409,
  "error": "CONFLICT",
  "message": "User with this email already exists",
  "timestamp": "2025-01-08T10:30:00Z"
}

// 429 Too Many Requests
{
  "status": 429,
  "error": "TOO_MANY_REQUESTS",
  "message": "Rate limit exceeded. Try again in 60 seconds.",
  "retryAfter": 60,
  "timestamp": "2025-01-08T10:30:00Z"
}
```

#### Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!@#",
  "deviceFingerprint": "device-fp-hash"
}
```

**Response: 200 OK**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "secure-random-refresh-token",
  "expiresIn": 900,
  "tokenType": "Bearer",
  "user": {
    "id": "firebase-uid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "roles": ["USER"],
    "permissions": [
      "read:own_profile",
      "write:own_profile"
    ],
    "status": "ACTIVE"
  },
  "requiresMFA": false
}
```

**MFA Required Response: 202 Accepted**
```json
{
  "requiresMFA": true,
  "mfaToken": "temporary-mfa-token",
  "challengeType": "OTP",
  "message": "MFA required. OTP sent to registered phone.",
  "expiresIn": 300
}
```

#### Verify MFA

```http
POST /auth/verify-mfa
Content-Type: application/json

{
  "mfaToken": "temporary-mfa-token",
  "otpCode": "123456"
}
```

**Response: 200 OK** (Same as login success response)

#### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "secure-random-refresh-token"
}
```

**Response: 200 OK**
```json
{
  "accessToken": "new-access-token",
  "refreshToken": "new-refresh-token",
  "expiresIn": 900,
  "tokenType": "Bearer"
}
```

#### Logout

```http
POST /auth/logout
Authorization: Bearer {accessToken}
```

**Response: 204 No Content**

#### Verify Email

```http
GET /auth/verify-email?token=email-verification-token
```

**Response: 200 OK**
```json
{
  "message": "Email verified successfully",
  "emailVerified": true,
  "status": "ACTIVE"
}
```

### User Management Endpoints

#### Get Current User Profile

```http
GET /users/profile
Authorization: Bearer {accessToken}
```

**Response: 200 OK**
```json
{
  "id": "firebase-uid",
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+254712345678",
  "roles": ["USER"],
  "permissions": ["read:own_profile", "write:own_profile"],
  "status": "ACTIVE",
  "emailVerified": true,
  "phoneVerified": false,
  "createdAt": "2025-01-01T10:00:00Z",
  "lastLoginAt": "2025-01-08T10:30:00Z"
}
```

#### Update Profile

```http
PUT /users/profile
Authorization: Bearer {accessToken}
Content-Type: application/json

{
  "firstName": "Jane",
  "lastName": "Smith",
  "phoneNumber": "+254712345679"
}
```

**Response: 200 OK** (Returns updated profile)

#### Get Active Sessions

```http
GET /users/sessions
Authorization: Bearer {accessToken}
```

**Response: 200 OK**
```json
{
  "sessions": [
    {
      "sessionId": "session-uuid-1",
      "deviceFingerprint": "device-hash",
      "ipAddress": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "createdAt": "2025-01-08T10:00:00Z",
      "lastActivityAt": "2025-01-08T10:30:00Z",
      "expiresAt": "2025-01-15T10:00:00Z",
      "current": true
    }
  ],
  "total": 1
}
```

#### Terminate Session

```http
DELETE /users/sessions/{sessionId}
Authorization: Bearer {accessToken}
```

**Response: 204 No Content**

### Admin Endpoints

#### List Pending Users

```http
GET /admin/users/pending
Authorization: Bearer {adminToken}
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
      "requestedRoles": ["MANAGER"],
      "status": "PENDING_APPROVAL",
      "canApprove": true,
      "approvalLevel": "ADMIN_OR_SUPER_ADMIN",
      "createdAt": "2025-01-05T10:00:00Z"
    }
  ],
  "total": 1,
  "page": 0,
  "pageSize": 20
}
```

#### Approve User

```http
POST /admin/users/{userId}/approve
Authorization: Bearer {adminToken}
Content-Type: application/json

{
  "approvedBy": "admin-user-id",
  "notes": "Credentials verified"
}
```

**Response: 200 OK**
```json
{
  "id": "user-uuid",
  "email": "approved@example.com",
  "status": "ACTIVE",
  "approvedBy": "admin-user-id",
  "approvedAt": "2025-01-08T10:30:00Z",
  "message": "User approved successfully"
}
```

#### Reject User

```http
POST /admin/users/{userId}/reject
Authorization: Bearer {adminToken}
Content-Type: application/json

{
  "rejectedBy": "admin-user-id",
  "reason": "Invalid credentials provided"
}
```

**Response: 200 OK**
```json
{
  "id": "user-uuid",
  "status": "REJECTED",
  "rejectedBy": "admin-user-id",
  "rejectedAt": "2025-01-08T10:30:00Z",
  "reason": "Invalid credentials provided"
}
```

#### Assign Role

```http
POST /admin/users/{userId}/roles
Authorization: Bearer {adminToken}
Content-Type: application/json

{
  "role": "MANAGER",
  "assignedBy": "admin-user-id"
}
```

**Response: 200 OK**

#### Revoke Role

```http
DELETE /admin/users/{userId}/roles/{role}
Authorization: Bearer {adminToken}
```

**Response: 204 No Content**

### Super Admin Endpoints

#### Bootstrap Super Admin

```http
POST /super-admin/register
Content-Type: application/json

{
  "email": "superadmin@example.com",
  "password": "VerySecurePass123!@#",
  "phoneNumber": "+254700000000"
}
```

**Response: 201 Created**
```json
{
  "id": "super-admin-uid",
  "email": "superadmin@example.com",
  "roles": ["SUPER_ADMIN"],
  "message": "Super Admin created successfully",
  "tempPasswordRequired": false
}
```

#### Super Admin Login

```http
POST /super-admin/login
Content-Type: application/json

{
  "email": "superadmin@example.com",
  "password": "VerySecurePass123!@#"
}
```

**Response: 200 OK** (Same structure as regular login)

### Rate Limit Headers

All API responses include rate limit headers:

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704456000
X-RateLimit-Retry-After: 60
```

---

## 🔒 Security

### Security Architecture

AuthSys implements a **Defense in Depth** strategy with multiple security layers:

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Network Security                               │
│ • TLS/SSL encryption                                    │
│ • IP whitelisting/blacklisting                          │
│ • DDoS protection (API Gateway)                         │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 2: Rate Limiting                                  │
│ • Global: 1000 req/min                                  │
│ • Per IP: 100 req/min (standard)                        │
│ • Per IP: 10 req/min (sensitive endpoints)              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Input Validation                               │
│ • XSS prevention                                        │
│ • SQL injection prevention                              │
│ • Request size limits                                   │
│ • Content-Type validation                               │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 4: Authentication                                 │
│ • Firebase ID token verification                        │
│ • Custom JWT validation (RS256)                         │
│ • Token blacklist checking                              │
│ • Session validation                                    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 5: Authorization                                  │
│ • RBAC role checking                                    │
│ • ABAC policy evaluation                                │
│ • Resource ownership verification                       │
│ • Permission caching                                    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 6: Data Protection                                │
│ • AES-256-GCM encryption for sensitive data             │
│ • Password hashing (bcrypt/scrypt via Firebase)         │
│ • PII masking in logs                                   │
│ • Secure key management                                 │
└─────────────────────────────────────────────────────────┘
```

### Password Policy

**Requirements:**
- Minimum length: 12 characters (configurable)
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- Cannot match any of the last 5 passwords
- Expires after 90 days (configurable)
- No common passwords (10,000+ blocked patterns)

**Implementation:**
```java
// Password validation
@Component
public class PasswordValidator {
    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("\\d");
    private static final Pattern SPECIAL = Pattern.compile("[!@#$%^&*(),.?\":{}|<>]");
    
    public ValidationResult validate(String password) {
        if (password.length() < 12) {
            return ValidationResult.fail("Minimum 12 characters required");
        }
        if (!UPPERCASE.matcher(password).find()) {
            return ValidationResult.fail("At least one uppercase letter required");
        }
        // ... additional checks
    }
}
```

### Rate Limiting

**Strategy: Token Bucket Algorithm (Bucket4j)**

| Endpoint Pattern | Limit | Window | Bucket |
|------------------|-------|--------|--------|
| `/auth/register` | 5 req | 1 min | per IP |
| `/auth/login` | 10 req | 1 min | per IP |
| `/auth/verify-otp` | 3 req | 5 min | per user |
| `/auth/forgot-password` | 3 req | 1 hour | per email |
| `/api/**` | 100 req | 1 min | per IP |
| Global | 1000 req | 1 min | all IPs |

**Redis Keys:**
```
rate:{endpoint}:{identifier}
rate:global
rate:user:{userId}
```

**Response on limit exceeded:**
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704456060
Retry-After: 60

{
  "status": 429,
  "error": "TOO_MANY_REQUESTS",
  "message": "Rate limit exceeded. Try again in 60 seconds.",
  "retryAfter": 60
}
```

### Account Security

#### Failed Login Protection

```
Attempt 1-3: Normal rate limiting
Attempt 4-5: Warning logged, increased monitoring
Attempt 6+:   Account locked for 30 minutes (exponential backoff)

Lockout Duration:
- 6th attempt:  30 minutes
- 7th attempt:  1 hour
- 8th attempt:  2 hours
- 9th attempt:  4 hours
- 10th attempt: 24 hours
```

**Implementation:**
```java
public Mono<Void> recordFailedLogin(String identifier) {
    String key = "login:failed:" + identifier;
    
    return redis.opsForValue()
        .increment(key)
        .flatMap(attempts -> {
            if (attempts >= 6) {
                Duration lockDuration = Duration.ofMinutes(
                    (long) Math.pow(2, attempts - 4) * 15
                );
                return lockAccount(identifier, lockDuration);
            }
            return Mono.empty();
        });
}
```

#### Session Management

**Limits:**
- Maximum concurrent sessions: 3 per user (configurable)
- Session timeout: 30 minutes of inactivity
- Absolute session lifetime: 7 days
- Session refresh: Rolling window on activity

**Session Invalidation:**
- Explicit logout
- Admin forced logout
- Password change
- Role change
- Account suspension
- Token expiry

### Risk-Based Authentication

**Risk Scoring (0-100):**

```java
Risk Score = (IP_Reputation × 0.30) + 
             (Device_Match × 0.25) + 
             (Login_Velocity × 0.20) + 
             (Geolocation × 0.15) + 
             (Time_Pattern × 0.10)
```

**Risk Actions:**
- **Score 0-30 (Low)**: Normal authentication
- **Score 31-70 (Medium)**: Additional logging, monitoring
- **Score 71-100 (High)**: MFA required, admin notification

**Risk Factors:**

| Factor | Indicators | Weight |
|--------|-----------|--------|
| IP Reputation | Known VPN, Tor, malicious IPs | 30% |
| Device Match | New device, changed fingerprint | 25% |
| Login Velocity | >3 logins in 15 minutes | 20% |
| Geolocation | Country change, impossible travel | 15% |
| Time Pattern | Unusual login hours | 10% |

### Encryption

**Data at Rest:**
- **Algorithm**: AES-256-GCM
- **Key Management**: Environment variables (production: AWS KMS/GCP Secret Manager)
- **IV**: Random, unique per encryption operation
- **Authentication**: GCM provides authenticated encryption

**Encrypted Data:**
- OTP codes (Redis)
- Temporary passwords
- Sensitive session fields
- API keys in configuration

**Implementation:**
```java
@Service
public class EncryptionService {
    private final SecretKey secretKey;
    
    public String encrypt(String plaintext) {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        
        // Combine IV + ciphertext
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }
}
```

### Token Security

**Access Token (JWT):**
- **Algorithm**: RS256 (RSA with SHA-256)
- **Lifetime**: 15 minutes
- **Key Rotation**: 30 days
- **Claims**: userId, roles, permissions, sessionId, deviceId

**Refresh Token:**
- **Format**: Cryptographically secure random (32 bytes)
- **Lifetime**: 7 days (rolling)
- **One-time use**: Consumed and rotated on refresh
- **Reuse detection**: Automatic revocation of token family

**Security Features:**
- Token blacklisting (Redis)
- Signature verification
- Expiry checking
- Issuer validation
- Audience validation

### Audit Logging

**All security events are logged:**

```json
{
  "eventId": "evt-uuid",
  "timestamp": "2025-01-08T10:30:00Z",
  "eventType": "LOGIN_SUCCESS",
  "actorId": "user-uid",
  "actorEmail": "u***r@example.com",
  "targetId": "resource-id",
  "action": "LOGIN",
  "result": "SUCCESS",
  "ipAddress": "192.168.1.100",
  "deviceFingerprint": "device-hash",
  "userAgent": "Mozilla/5.0...",
  "location": {
    "country": "KE",
    "city": "Nairobi"
  },
  "metadata": {
    "riskScore": 25,
    "mfaUsed": false
  }
}
```

**Logged Events:**
- `USER_REGISTERED`
- `LOGIN_SUCCESS` / `LOGIN_FAILED`
- `MFA_REQUIRED` / `MFA_SUCCESS` / `MFA_FAILED`
- `PASSWORD_CHANGED`
- `ACCOUNT_LOCKED` / `ACCOUNT_UNLOCKED`
- `ROLE_ASSIGNED` / `ROLE_REVOKED`
- `SESSION_CREATED` / `SESSION_TERMINATED`
- `TOKEN_REFRESHED` / `TOKEN_REVOKED`
- `ADMIN_ACTION`

### Security Headers

All responses include security headers:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

### Compliance

**GDPR Compliance:**
- ✅ Right to access (user profile endpoint)
- ✅ Right to rectification (profile update)
- ✅ Right to erasure (account deletion)
- ✅ Data portability (export endpoint)
- ✅ Consent management
- ✅ Audit trail for data access

**SOC2 Controls:**
- ✅ Access controls (RBAC/ABAC)
- ✅ Encryption at rest and in transit
- ✅ Audit logging
- ✅ Change management
- ✅ Incident response procedures

---

## 📊 Monitoring

### Prometheus Metrics

**Authentication Metrics:**
```
# Login metrics
auth_login_total{result="success|failure",risk_level="low|medium|high"}
auth_login_duration_seconds
auth_mfa_required_total
auth_mfa_success_rate

# Registration metrics
auth_registration_total{status="success|failure"}
auth_email_verification_rate

# Token metrics
auth_token_refresh_total
auth_token_reuse_detected_total
auth_token_blacklist_size

# Session metrics
auth_sessions_active
auth_sessions_created_total
auth_sessions_expired_total
```

**Security Metrics:**
```
# Rate limiting
auth_rate_limit_hits_total{endpoint="..."}
auth_rate_limit_blocked_total

# Account security
auth_account_lockout_total
auth_failed_login_attempts_total
auth_suspicious_activity_total
```

**Performance Metrics:**
```
# External services
auth_firebase_call_duration_seconds{operation="verify_token|create_user"}
auth_redis_operation_duration_seconds{operation="get|set|delete"}

# Cache performance
auth_cache_hit_rate{cache_type="session|user|permission"}
auth_cache_miss_total
```

### Grafana Dashboards

**Authentication Overview Dashboard:**
- Login success/failure rates (last 24h)
- MFA trigger rate
- Average risk scores
- Active sessions count
- Registration funnel

**Security Dashboard:**
- Failed login attempts (heatmap)
- Account lockouts
- Rate limit violations
- Suspicious activity alerts
- Token reuse detections

**Performance Dashboard:**
- Request latency (p50, p95, p99)
- Firebase call latency
- Redis operation latency
- Cache hit rates
- Error rates

### Health Checks

**Liveness Probe:**
```bash
curl http://localhost:8001/actuator/health/liveness
```

**Response:**
```json
{
  "status": "UP"
}
```

**Readiness Probe:**
```bash
curl http://localhost:8001/actuator/health/readiness
```

**Response:**
```json
{
  "status": "UP",
  "components": {
    "redis": {"status": "UP"},
    "firestore": {"status": "UP"},
    "diskSpace": {"status": "UP"}
  }
}
```

**Custom Health Indicator:**
```java
@Component
public class BootstrapHealthIndicator implements HealthIndicator {
    
    @Override
    public Health health() {
        boolean isComplete = checkBootstrapComplete();
        int criticalFailures = countCriticalFailures();
        
        if (!isComplete || criticalFailures > 0) {
            return Health.down()
                .withDetail("isComplete", isComplete)
                .withDetail("criticalFailures", criticalFailures)
                .build();
        }
        
        return Health.up()
            .withDetail("isComplete", true)
            .withDetail("lastAttempt", getLastAttemptTime())
            .build();
    }
}
```

### Distributed Tracing

**OpenTelemetry Integration:**

```yaml
# application.yml
management:
  tracing:
    sampling:
      probability: 1.0  # Sample 100% in dev, 0.1 in prod
  otlp:
    tracing:
      endpoint: http://otel-collector:4318/v1/traces
```

**Trace Example:**
```
Span: POST /auth/login
├── Span: RateLimitCheck (2ms)
├── Span: LoadUserFromCache (5ms)
│   └── Span: RedisGet (3ms)
├── Span: VerifyFirebaseToken (150ms)
│   └── Span: FirebaseHTTPCall (145ms)
├── Span: RiskScoring (25ms)
│   ├── Span: CheckIPReputation (10ms)
│   └── Span: AnalyzeVelocity (8ms)
├── Span: GenerateTokens (20ms)
└── Span: CreateSession (15ms)
    ├── Span: SaveToRedis (5ms)
    └── Span: SaveToFirestore (10ms)

Total Duration: 217ms
```

### Alerting Rules

**Critical Alerts:**
```yaml
# Prometheus Alert Rules
groups:
  - name: authentication_critical
    rules:
      - alert: HighFailedLoginRate
        expr: rate(auth_login_total{result="failure"}[5m]) > 0.5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High failed login rate detected"
          
      - alert: TokenReuseDetected
        expr: increase(auth_token_reuse_detected_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Refresh token reuse detected - possible attack"
          
      - alert: FirebaseDown
        expr: up{job="firebase"} == 0
        for: 2m
        labels:
          severity: critical
          
  - name: authentication_warning
    rules:
      - alert: HighRiskLogins
        expr: rate(auth_login_total{risk_level="high"}[15m]) > 0.1
        for: 10m
        labels:
          severity: warning
```

---

## 🚢 Deployment

### Production Deployment Checklist

- [ ] **Configuration**
    - [ ] Update `application-production.yml` with production values
    - [ ] Set all environment variables
    - [ ] Configure Firebase production project
    - [ ] Set up Redis cluster/managed service
    - [ ] Configure SSL/TLS certificates

- [ ] **Security**
    - [ ] Rotate all secrets and API keys
    - [ ] Configure firewall rules
    - [ ] Set up IP whitelisting
    - [ ] Enable audit logging
    - [ ] Configure backup encryption

- [ ] **Monitoring**
    - [ ] Set up Prometheus scraping
    - [ ] Configure Grafana dashboards
    - [ ] Set up alerting (PagerDuty/Opsgenie)
    - [ ] Configure log aggregation
    - [ ] Enable distributed tracing

- [ ] **Testing**
    - [ ] Run security scan (OWASP ZAP)
    - [ ] Perform load testing (k6)
    - [ ] Verify backup/restore procedures
    - [ ] Test failover scenarios
    - [ ] Validate monitoring alerts

- [ ] **Documentation**
    - [ ] Update runbooks
    - [ ] Document incident response procedures
    - [ ] Create deployment guide
    - [ ] Update API documentation

### Docker Deployment

**Dockerfile:**
```dockerfile
FROM eclipse-temurin:21-jre-alpine AS runtime

# Security: Run as non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy application
COPY target/authSys-*.jar app.jar

# Set ownership
RUN chown -R appuser:appgroup /app

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8001/actuator/health/liveness || exit 1

EXPOSE 8001

# JVM options
ENV JAVA_OPTS="-XX:+UseG1GC -XX:MaxRAMPercentage=75.0 -XX:+HeapDumpOnOutOfMemoryError"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
```

**Build and run:**
```bash
# Build
docker build -t authsys:1.0.0 .

# Run
docker run -d \
  --name authsys \
  -p 8001:8001 \
  -e SPRING_PROFILES_ACTIVE=production \
  -e FIREBASE_PROJECT_ID=${FIREBASE_PROJECT_ID} \
  -e REDIS_HOST=redis.production.internal \
  -v /etc/secrets/firebase:/app/config/firebase:ro \
  authsys:1.0.0
```

### Kubernetes Deployment

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authsys
  namespace: production
  labels:
    app: authsys
    version: v1.0.0
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: authsys
  template:
    metadata:
      labels:
        app: authsys
        version: v1.0.0
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8001"
        prometheus.io/path: "/actuator/prometheus"
    spec:
      serviceAccountName: authsys
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      
      containers:
      - name: authsys
        image: your-registry/authsys:1.0.0
        imagePullPolicy: Always
        
        ports:
        - containerPort: 8001
          name: http
          protocol: TCP
        
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "production"
        - name: REDIS_HOST
          valueFrom:
            configMapKeyRef:
              name: authsys-config
              key: redis-host
        - name: FIREBASE_PROJECT_ID
          valueFrom:
            secretKeyRef:
              name: authsys-secrets
              key: firebase-project-id
        - name: ENCRYPTION_KEY
          valueFrom:
            secretKeyRef:
              name: authsys-secrets
              key: encryption-key
        
        resources:
          requests:
            cpu: "500m"
            memory: "1Gi"
          limits:
            cpu: "2000m"
            memory: "2Gi"
        
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8001
          initialDelaySeconds: 60
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8001
          initialDelaySeconds: 30
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        
        volumeMounts:
        - name: firebase-credentials
          mountPath: /app/config/firebase
          readOnly: true
        - name: logs
          mountPath: /app/logs
      
      volumes:
      - name: firebase-credentials
        secret:
          secretName: firebase-credentials
      - name: logs
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: authsys
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: authsys
  ports:
  - port: 80
    targetPort: 8001
    protocol: TCP
    name: http

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: authsys-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: authsys
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 30
```

**Deploy:**
```bash
# Create namespace
kubectl create namespace production

# Create secrets
kubectl create secret generic authsys-secrets \
  --from-literal=firebase-project-id=your-project-id \
  --from-literal=encryption-key=your-encryption-key \
  -n production

# Deploy
kubectl apply -f k8s/ -n production

# Verify
kubectl get pods -n production
kubectl logs -f deployment/authsys -n production
```

---

## 👨‍💻 Development

### Prerequisites

- Java 21 JDK
- Maven 3.9+
- Redis 7.x
- IntelliJ IDEA or VS Code
- Postman or cURL

### Development Setup

```bash
# Clone
git clone https://github.com/your-org/authsys.git
cd authsys

# Install dependencies
mvn clean install

# Run tests
mvn test

# Run with dev profile
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

### Code Style

This project follows the **Google Java Style Guide**.

**Format code:**
```bash
mvn spotless:apply
```

**Check formatting:**
```bash
mvn spotless:check
```

### Testing

**Unit Tests:**
```bash
mvn test
```

**Integration Tests:**
```bash
mvn verify -P integration-tests
```

**Coverage Report:**
```bash
mvn jacoco:report
# Open target/site/jacoco/index.html
```

**Target Coverage: 80%+**

### Debugging

**Enable debug logging:**
```properties
logging.level.com.techStack.authSys=DEBUG
logging.level.org.springframework.security=TRACE
```

**Remote debugging:**
```bash
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=5005"
```

---

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Add tests** (maintain 80%+ coverage)
5. **Run tests**
   ```bash
   mvn test
   ```
6. **Commit with clear messages**
   ```bash
   git commit -m "feat: add amazing feature"
   ```
7. **Push to your fork**
   ```bash
   git push origin feature/amazing-feature
   ```
8. **Submit a Pull Request**

### Pull Request Requirements

- ✅ Passing CI/CD pipeline
- ✅ Code review from maintainer
- ✅ Test coverage ≥ 80%
- ✅ Updated documentation
- ✅ No security vulnerabilities
- ✅ Follows code style guide

---

## 📝 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 📧 Support & Contact

**Maintainer:** Fixtone Kaloki  
**Email:** fixtone94tec@gmail.com  
**GitHub:** [@94tec](https://github.com/94tec)

### Getting Help

- **Bugs & Feature Requests:** [Create an Issue](https://github.com/your-org/authsys/issues)
- **Security Vulnerabilities:** Email fixtone94tec@gmail.com directly
- **Questions:** [Discussions](https://github.com/your-org/authsys/discussions)

---

## 🙏 Acknowledgments

- **Spring Framework Team** - Excellent reactive support
- **Firebase Team** - Robust authentication services
- **Redis Community** - High-performance caching
- **All Contributors** - Thank you for your contributions!

---

## 📚 Additional Resources

- [Spring Boot Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [Firebase Documentation](https://firebase.google.com/docs)
- [Redis Documentation](https://redis.io/documentation)
- [Project Reactor](https://projectreactor.io/docs)
- [OpenTelemetry](https://opentelemetry.io/docs/)

---

**Built with ❤️ by the AuthSys Team**