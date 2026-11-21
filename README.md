# AuthSys

**Reactive authentication and authorization microservice** built on Spring WebFlux, Firebase Auth, Firestore and Redis.

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
<!-- Replace with your real CI badge once the workflow exists:
[![CI](https://github.com/<org>/<repo>/actions/workflows/ci.yml/badge.svg)](https://github.com/<org>/<repo>/actions/workflows/ci.yml)
-->

AuthSys handles registration, login, token issuance, sessions, role and attribute-based access control, user approval workflows, audit logging and notifications. It is stateless, so it scales horizontally behind a load balancer.

---

## Table of contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Technology stack](#technology-stack)
4. [Quick start](#quick-start)
5. [Configuration](#configuration)
6. [API reference](#api-reference)
7. [Security](#security)
8. [Observability](#observability)
9. [Deployment](#deployment)
10. [Operations runbook](#operations-runbook)
11. [Development](#development)
12. [Contributing](#contributing)
13. [License and support](#license-and-support)

---

## Features

**Authentication**
- Registration with email and phone verification
- Risk-scored login with step-up MFA (OTP by SMS)
- Access and refresh tokens, with refresh rotation and reuse detection
- Redis-backed sessions with a concurrent-session limit

**Authorization**
- Hierarchical RBAC: `SUPER_ADMIN` → `ADMIN` → `MANAGER` → `USER`
- ABAC policies evaluated with SpEL over user, resource, time and IP attributes
- Roles and permissions defined in YAML, cached with a short TTL

**User management**
- Approval workflow: `PENDING_VERIFICATION` → `PENDING_APPROVAL` → `ACTIVE` | `REJECTED` | `SUSPENDED`
- Role assignment and revocation with an audit trail
- Super Admin bootstrap on first start

**Platform**
- Fully non-blocking (Project Reactor end to end)
- Firebase Auth is the source of identity; Firestore holds profiles, sessions and audit logs; Redis holds caches, rate-limit state and OTPs
- Prometheus metrics, OpenTelemetry tracing, structured audit events
- Circuit breakers and retries (Resilience4j) around external calls

---

## Architecture

```
                 ┌───────────────────────────────┐
                 │  API gateway / load balancer  │
                 │  TLS termination, coarse WAF  │
                 └───────────────┬───────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            ▼                    ▼                    ▼
      AuthSys pod 1        AuthSys pod 2        AuthSys pod N
            │                    │                    │
            └────────────────────┼────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
   Firebase Auth             Firestore                 Redis
   (identity)                (durable data)            (cache, limits, OTP)
```

### Request pipeline

1. **Rate limit** (Bucket4j, state in Redis)
2. **Token validation**: signature, expiry, issuer, audience, blacklist check
3. **User context**: Redis lookup, Firestore fallback, permission resolution
4. **Authorization**: RBAC, then ABAC policies, then allow or deny
5. **Business logic**
6. **Audit event and metrics**

### Data strategy

| Data | Redis | Firestore | Pattern |
|------|-------|-----------|---------|
| Sessions | primary read | durable copy | cache-aside, write-through |
| User profile | TTL 1 h | source of truth | cache-aside |
| Permissions | TTL 15 min | source of truth | cache-aside |
| Audit logs | no | only | write-only |
| Rate limits, OTPs | only | no | cache-only |

### Redis key layout

```
session:access:{id}        session:refresh:{token}
rate:{endpoint}:{id}       rate:global
user:profile:{uid}         user:permissions:{uid}
otp:activation:{uid}       otp:attempts:{uid}
blacklist:token:{jti}      login:failed:{identifier}
```

---

## Technology stack

| Area | Technology |
|------|-----------|
| Language and runtime | Java 21 |
| Framework | Spring Boot 3.2.x, Spring WebFlux (Netty), Spring Security 6.2 |
| Reactive | Project Reactor, Lettuce (reactive Redis) |
| Identity and data | Firebase Admin SDK, Cloud Firestore |
| Cache | Redis 7 |
| Tokens | Nimbus JOSE+JWT |
| Rate limiting | Bucket4j |
| Resilience | Resilience4j |
| Notifications | Brevo (email), Africa's Talking (SMS) |
| Observability | Micrometer, Prometheus, OpenTelemetry |
| Build and test | Maven 3.9, JUnit 5, Reactor Test |
| Packaging | Docker, Kubernetes |

---

## Quick start

### Prerequisites

- Java 21 JDK and Maven 3.9+
- Redis 7 reachable from the app
- A Firebase project with Authentication and Firestore enabled
- A Firebase service account key (see below)
- Optional: Brevo and Africa's Talking credentials for email and SMS

### 1. Clone

```bash
git clone https://github.com/<org>/<repo>.git
cd <repo>
```

### 2. Provide Firebase credentials

In the Firebase console, open **Project settings → Service accounts → Generate new private key**.

**Keep the key out of the repository.** Store it outside the source tree and point to it:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=$HOME/secrets/firebase-service-account.json
```

Make sure `.gitignore` contains:

```gitignore
firebase-service-account*.json
application-local.properties
.env
```

If a key was ever committed, treat it as compromised: revoke it in the Firebase console and generate a new one.

### 3. Configure

```bash
cp src/main/resources/application.properties.example \
   src/main/resources/application-local.properties
```

Minimum settings:

```properties
server.port=8001

firebase.project-id=your-firebase-project-id
firebase.api-key=your-firebase-web-api-key

spring.data.redis.host=localhost
spring.data.redis.port=6379

app.super-admin.email=admin@example.com
app.super-admin.phone=+254700000000
```

### 4. Build and run

```bash
mvn clean verify
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

Or run the jar:

```bash
java -jar target/authSys-0.0.1-SNAPSHOT.jar --spring.profiles.active=local
```

### 5. Verify

```bash
curl -s http://localhost:8001/actuator/health | jq
```

A healthy instance reports `"status": "UP"` with `redis` and `firestore` components. The bootstrap indicator appears as a component of the same response.

### Run with Docker Compose

```bash
cp .env.example .env     # fill in values; never commit .env
docker compose up -d --build
docker compose logs -f authsys
```

`docker-compose.yml`:

```yaml
services:
  authsys:
    build: .
    ports:
      - "8001:8001"
    env_file: .env
    environment:
      SPRING_PROFILES_ACTIVE: production
      REDIS_HOST: redis
      GOOGLE_APPLICATION_CREDENTIALS: /run/secrets/firebase.json
    secrets:
      - source: firebase
        target: firebase.json
    depends_on:
      redis:
        condition: service_healthy
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "${REDIS_PASSWORD}", "--appendonly", "yes"]
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASSWORD}", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    volumes:
      - redis-data:/data
    restart: unless-stopped

secrets:
  firebase:
    file: ./secrets/firebase-service-account.json

volumes:
  redis-data:
```

Redis is not published to the host in this file on purpose. Only the app needs to reach it.

---

## Configuration

All settings can be overridden with environment variables. Never commit real secrets.

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SPRING_PROFILES_ACTIVE` | yes (prod) | `dev` | Use `production` in live environments |
| `FIREBASE_PROJECT_ID` | yes | none | Firebase project id |
| `FIREBASE_API_KEY` | yes | none | Firebase web API key |
| `GOOGLE_APPLICATION_CREDENTIALS` | yes | none | Path to the service account JSON |
| `REDIS_HOST` | yes | `localhost` | Redis host |
| `REDIS_PORT` | no | `6379` | Redis port |
| `REDIS_PASSWORD` | yes (prod) | empty | Redis password |
| `ENCRYPTION_KEY` | yes | none | Base64 32-byte AES-256 key |
| `JWT_PRIVATE_KEY` | yes | none | Base64 RSA private key (token signing) |
| `JWT_PUBLIC_KEY` | yes | none | Base64 RSA public key (verification) |
| `SUPER_ADMIN_EMAIL` | first start | none | Bootstrap Super Admin email |
| `SUPER_ADMIN_PHONE` | first start | none | Bootstrap Super Admin phone |
| `SUPER_ADMIN_AUTO_CREATE` | no | `true` | Set to `false` after the first successful start |
| `BREVO_API_KEY` | for email | none | Brevo API key |
| `BREVO_SENDER_EMAIL` | for email | none | Verified sender address |
| `AT_USERNAME`, `AT_API_KEY` | for SMS | `sandbox` | Africa's Talking credentials |
| `APP_BASE_URL` | yes | `http://localhost:8001` | Public URL of this service (used in email links) |
| `APP_FRONTEND_URL` | yes | `http://localhost:3000` | Frontend origin |
| `OTLP_ENDPOINT` | no | `http://localhost:4318/v1/traces` | OpenTelemetry collector |

Generate keys:

```bash
# AES-256 key
openssl rand -base64 32

# RSA key pair for JWT signing
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
```

### Production profile

`application-production.properties` should tighten the development defaults:

```properties
# Logging: no framework debug output in production
logging.level.root=INFO
logging.level.com.techStack.authSys=INFO
logging.level.org.springframework.security=WARN

# Graceful shutdown
server.shutdown=graceful
spring.lifecycle.timeout-per-shutdown-phase=30s

# Actuator: expose only what operators need
management.endpoints.web.exposure.include=health,info,prometheus
management.endpoint.health.probes.enabled=true
management.endpoint.health.show-details=when-authorized
management.prometheus.metrics.export.enabled=true

# Tracing: sample a fraction of traffic
management.tracing.sampling.probability=0.1

# CORS: list exact origins, no wildcards
auth.security.cors.allowed-origins=https://app.example.com
auth.security.cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
auth.security.cors.max-age=3600
```

### Security and session settings

```properties
# Tokens
auth.jwt.access-token-ttl=900            # 15 minutes
auth.jwt.refresh-token-ttl=604800        # 7 days
auth.jwt.key-rotation-days=30

# Rate limiting
security.rate-limit.enabled=true
security.rate-limit.global=1000
security.rate-limit.ip-standard=100
security.rate-limit.ip-sensitive=10
security.rate-limit.window-minutes=1

# Passwords
security.password.min-length=12
security.password.require-uppercase=true
security.password.require-lowercase=true
security.password.require-digit=true
security.password.require-special=true
security.password.expiry-days=90
security.password.history-count=5

# Lockout
security.account.max-failed-attempts=5
security.account.lockout-duration-minutes=30

# Sessions
session.timeout-minutes=30
session.max-concurrent=3
session.refresh-token-rotation=true
```

### Roles and policies

`permissions.yaml`:

```yaml
roles:
  SUPER_ADMIN:
    permissions: ["*:*"]
    priority: 100
  ADMIN:
    inherits: [MANAGER, USER]
    permissions: ["read:*", "write:*", "delete:users", "manage:roles", "approve:all"]
    priority: 50
  MANAGER:
    inherits: [USER]
    permissions: ["read:team_data", "write:team_data", "approve:user_requests", "manage:team_members"]
    attributes:
      max_approval_amount: 10000
    priority: 30
  USER:
    permissions: ["read:own_profile", "write:own_profile", "read:public_documents", "create:requests"]
    priority: 10

policies:
  resource_ownership:
    - name: "Owner full access"
      effect: ALLOW
      conditions: ["resource.ownerId == user.id"]
  department_access:
    - name: "Department read access"
      effect: ALLOW
      conditions: ["resource.department == user.department", "action == 'read'"]
  business_hours:
    - name: "After hours restriction"
      effect: DENY
      conditions:
        - "time.hour >= 22 || time.hour <= 6"
        - "user.role != 'ADMIN'"
        - "user.role != 'SUPER_ADMIN'"
```

---

## API reference

| Environment | Base URL |
|-------------|----------|
| Local | `http://localhost:8001/api` |
| Production | `https://api.example.com/api` |

Authenticated endpoints expect `Authorization: Bearer <accessToken>`.

### Error format

```json
{
  "status": 409,
  "error": "CONFLICT",
  "message": "User with this email already exists",
  "timestamp": "2025-01-08T10:30:00Z"
}
```

Common statuses: `400` validation, `401` missing or invalid token, `403` not permitted, `409` conflict, `429` rate limited (see `Retry-After`).

### Authentication

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/auth/register` | none | Register a user |
| POST | `/auth/login` | none | Log in; may return an MFA challenge |
| POST | `/auth/verify-mfa` | MFA token | Complete an MFA challenge |
| POST | `/auth/refresh` | refresh token | Rotate tokens |
| POST | `/auth/logout` | bearer | End the current session |
| GET | `/auth/verify-email?token=` | none | Confirm an email address |

**Register**

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

`201 Created`

```json
{
  "id": "firebase-uid",
  "email": "user@example.com",
  "status": "PENDING_VERIFICATION",
  "roles": ["USER"],
  "message": "Registration successful. Please verify your email.",
  "verificationRequired": true
}
```

**Login**

```http
POST /auth/login
Content-Type: application/json

{ "email": "user@example.com", "password": "SecurePass123!@#", "deviceFingerprint": "device-fp-hash" }
```

`200 OK`

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "opaque-refresh-token",
  "expiresIn": 900,
  "tokenType": "Bearer",
  "user": { "id": "firebase-uid", "email": "user@example.com", "roles": ["USER"], "status": "ACTIVE" },
  "requiresMFA": false
}
```

`202 Accepted` when step-up MFA is required:

```json
{
  "requiresMFA": true,
  "mfaToken": "temporary-mfa-token",
  "challengeType": "OTP",
  "expiresIn": 300
}
```

Complete it with `POST /auth/verify-mfa` and `{ "mfaToken": "...", "otpCode": "123456" }`.

**Refresh**

```http
POST /auth/refresh
{ "refreshToken": "opaque-refresh-token" }
```

Refresh tokens are single use. Reusing a consumed token revokes the whole token family and forces a new login.

### Users

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/users/profile` | Current user's profile |
| PUT | `/users/profile` | Update first name, last name, phone |
| GET | `/users/sessions` | List active sessions |
| DELETE | `/users/sessions/{sessionId}` | Terminate a session |

### Admin

Requires `ADMIN` or `SUPER_ADMIN`. Some actions have stricter approval levels.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/admin/users/pending` | Users awaiting approval |
| POST | `/admin/users/{userId}/approve` | Approve a user |
| POST | `/admin/users/{userId}/reject` | Reject a user (reason required) |
| POST | `/admin/users/{userId}/roles` | Assign a role |
| DELETE | `/admin/users/{userId}/roles/{role}` | Revoke a role |

### Super Admin

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/super-admin/register` | Create the first Super Admin |
| POST | `/super-admin/login` | Super Admin login |

> **Production note:** after the first Super Admin exists, set `SUPER_ADMIN_AUTO_CREATE=false` and restrict `/super-admin/register` at the gateway (internal network or IP allowlist only).

### Rate-limit headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704456000
Retry-After: 60            # only on 429
```

---

## Security

### Layers

1. **Network**: TLS everywhere; DDoS protection and IP filtering at the gateway
2. **Rate limiting**: token bucket per IP, user or email
3. **Input validation**: request size limits, content-type checks, sanitisation
4. **Authentication**: Firebase ID tokens and RS256 JWTs, token blacklist, session validation
5. **Authorization**: RBAC, ABAC, resource ownership checks
6. **Data protection**: AES-256-GCM for sensitive fields, PII masked in logs

### Rate limits

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| `/auth/register` | 5 | 1 min | IP |
| `/auth/login` | 10 | 1 min | IP |
| `/auth/verify-otp` | 3 | 5 min | user |
| `/auth/forgot-password` | 3 | 1 hour | email |
| `/api/**` | 100 | 1 min | IP |
| Global | 1000 | 1 min | all |

### Passwords

- Minimum 12 characters with upper, lower, digit and special character
- Cannot repeat any of the last 5 passwords
- Common-password blocklist
- Expires after 90 days (configurable)
- Hashing is handled by Firebase Auth

### Account lockout

After 5 failed attempts the account locks, with exponential backoff:

| Failed attempt | Lock duration |
|----------------|---------------|
| 6 | 30 minutes |
| 7 | 1 hour |
| 8 | 2 hours |
| 9 | 4 hours |
| 10 and above | 24 hours |

```java
Duration lock = Duration.ofMinutes(
    Math.min(30L * (1L << Math.min(attempts - 6, 10)), 1440L)
);
```

### Sessions

- Up to 3 concurrent sessions per user (configurable)
- 30 minute idle timeout, 7 day absolute lifetime
- Sessions are invalidated on logout, admin action, password change, role change, suspension and token expiry

### Risk-based authentication

A score from 0 to 100 is computed per login:

| Factor | Weight |
|--------|--------|
| IP reputation | 30% |
| Device match | 25% |
| Login velocity | 20% |
| Geolocation | 15% |
| Time pattern | 10% |

Low (0-30) proceeds normally, medium (31-70) adds logging, high (71-100) requires MFA and notifies admins.

### Tokens

| | Access token | Refresh token |
|-|--------------|---------------|
| Format | JWT, RS256 | 32 random bytes, opaque |
| Lifetime | 15 minutes | 7 days, rolling |
| Use | every API call | once, then rotated |
| Revocation | blacklist by `jti` | family revocation on reuse |

Rotate signing keys every 30 days and keep the previous public key published until outstanding tokens expire.

### Encryption

AES-256-GCM with a random 96-bit IV per operation, stored as `IV || ciphertext` in Base64. Applied to OTP codes, temporary passwords and sensitive session fields. Keep `ENCRYPTION_KEY` in a secret manager and never in source control or application properties.

### Audit log

Every security-relevant action produces a structured, append-only event in Firestore:

```json
{
  "eventId": "evt-uuid",
  "timestamp": "2025-01-08T10:30:00Z",
  "eventType": "LOGIN_SUCCESS",
  "actorId": "user-uid",
  "actorEmail": "u***r@example.com",
  "action": "LOGIN",
  "result": "SUCCESS",
  "ipAddress": "192.168.1.100",
  "metadata": { "riskScore": 25, "mfaUsed": false }
}
```

Events include: `USER_REGISTERED`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `MFA_REQUIRED`, `MFA_SUCCESS`, `MFA_FAILED`, `PASSWORD_CHANGED`, `ACCOUNT_LOCKED`, `ACCOUNT_UNLOCKED`, `ROLE_ASSIGNED`, `ROLE_REVOKED`, `SESSION_CREATED`, `SESSION_TERMINATED`, `TOKEN_REFRESHED`, `TOKEN_REVOKED`, `ADMIN_ACTION`.

### Response headers

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store
```

### Compliance posture

AuthSys provides controls that support GDPR and SOC 2 programmes: access control, encryption in transit and at rest, audit logging and user data access and correction. Compliance itself depends on how you deploy and operate the service, your data-processing agreements and your own policies. It is not a certification.

### Reporting a vulnerability

Please do not open a public issue. Email the maintainer (see [Support](#license-and-support)) with details and reproduction steps. Expect an acknowledgement within a few days.

---

## Observability

### Health

| Endpoint | Use |
|----------|-----|
| `/actuator/health/liveness` | Kubernetes liveness probe |
| `/actuator/health/readiness` | Readiness probe (Redis, Firestore) |
| `/actuator/health` | Full status, including bootstrap indicator |
| `/actuator/prometheus` | Metrics scrape |

**Do not expose `/actuator/**` to the public internet.** Route it only on an internal port or network, or protect it at the gateway.

### Key metrics

```
auth_login_total{result,risk_level}        auth_login_duration_seconds
auth_mfa_required_total                    auth_registration_total{status}
auth_token_refresh_total                   auth_token_reuse_detected_total
auth_sessions_active                       auth_account_lockout_total
auth_rate_limit_blocked_total              auth_failed_login_attempts_total
auth_firebase_call_duration_seconds        auth_redis_operation_duration_seconds
auth_cache_hit_rate{cache_type}
```

### Suggested alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| High failed-login rate | `rate(auth_login_total{result="failure"}[5m]) > 0.5` for 5 min | critical |
| Refresh-token reuse | `increase(auth_token_reuse_detected_total[5m]) > 0` | critical |
| Readiness failing | readiness probe down for 2 min | critical |
| High-risk logins | `rate(auth_login_total{risk_level="high"}[15m]) > 0.1` for 10 min | warning |
| p95 latency | p95 request duration above your SLO for 10 min | warning |

### Tracing

OpenTelemetry traces are exported over OTLP to `OTLP_ENDPOINT`. Every request carries a correlation id that appears in logs and audit events. Keep sampling at 10% or lower in production.

---

## Deployment

### Pre-launch checklist

**Secrets and configuration**
- [ ] `production` profile active; no secrets in the repo or image
- [ ] Firebase production project, service account stored in a secret manager
- [ ] `ENCRYPTION_KEY`, JWT key pair and `REDIS_PASSWORD` generated and stored securely
- [ ] CORS lists exact production origins
- [ ] `SUPER_ADMIN_AUTO_CREATE=false` after the first start

**Network**
- [ ] TLS terminated and enforced; HTTP redirected to HTTPS
- [ ] Redis not reachable from the internet
- [ ] `/actuator/**` and `/super-admin/**` restricted
- [ ] Gateway rate limiting and IP filtering on

**Reliability**
- [ ] At least 2 replicas, with readiness and liveness probes
- [ ] Redis persistence or a managed Redis with backups
- [ ] Firestore backups and a tested restore
- [ ] Graceful shutdown verified during a rolling update

**Visibility**
- [ ] Prometheus scraping, dashboards and alerts live
- [ ] Logs shipped to central storage with retention set
- [ ] Traces reaching the collector

**Verification**
- [ ] Load test of login and refresh at expected peak
- [ ] Dependency and container scan clean (OWASP Dependency-Check, Trivy)
- [ ] Smoke test: register, verify, login, refresh, logout

### Docker

```dockerfile
# Build stage
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /src/target/authSys-*.jar app.jar
RUN mkdir -p /app/logs && chown -R app:app /app
USER app

ENV JAVA_OPTS="-XX:+UseG1GC -XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD wget -qO- http://localhost:8001/actuator/health/liveness || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
```

```bash
docker build -t authsys:1.0.0 .
docker run -d --name authsys -p 8001:8001 \
  --env-file .env \
  -e SPRING_PROFILES_ACTIVE=production \
  -e GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/firebase.json \
  -v /etc/secrets/firebase.json:/run/secrets/firebase.json:ro \
  authsys:1.0.0
```

Pin image tags to a version, never `latest`, in production.

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authsys
  namespace: production
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate: { maxSurge: 1, maxUnavailable: 0 }
  selector:
    matchLabels: { app: authsys }
  template:
    metadata:
      labels: { app: authsys }
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8001"
        prometheus.io/path: "/actuator/prometheus"
    spec:
      securityContext: { runAsNonRoot: true, runAsUser: 1000, fsGroup: 1000 }
      terminationGracePeriodSeconds: 45
      containers:
        - name: authsys
          image: your-registry/authsys:1.0.0
          ports: [{ containerPort: 8001, name: http }]
          env:
            - { name: SPRING_PROFILES_ACTIVE, value: production }
            - { name: GOOGLE_APPLICATION_CREDENTIALS, value: /app/config/firebase/key.json }
            - name: REDIS_HOST
              valueFrom: { configMapKeyRef: { name: authsys-config, key: redis-host } }
            - name: REDIS_PASSWORD
              valueFrom: { secretKeyRef: { name: authsys-secrets, key: redis-password } }
            - name: ENCRYPTION_KEY
              valueFrom: { secretKeyRef: { name: authsys-secrets, key: encryption-key } }
            - name: JWT_PRIVATE_KEY
              valueFrom: { secretKeyRef: { name: authsys-secrets, key: jwt-private-key } }
            - name: JWT_PUBLIC_KEY
              valueFrom: { secretKeyRef: { name: authsys-secrets, key: jwt-public-key } }
          resources:
            requests: { cpu: 500m, memory: 1Gi }
            limits: { cpu: "2", memory: 2Gi }
          startupProbe:
            httpGet: { path: /actuator/health/liveness, port: 8001 }
            periodSeconds: 5
            failureThreshold: 24
          livenessProbe:
            httpGet: { path: /actuator/health/liveness, port: 8001 }
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet: { path: /actuator/health/readiness, port: 8001 }
            periodSeconds: 5
            failureThreshold: 3
          volumeMounts:
            - { name: firebase, mountPath: /app/config/firebase, readOnly: true }
      volumes:
        - name: firebase
          secret: { secretName: firebase-credentials }
---
apiVersion: v1
kind: Service
metadata: { name: authsys, namespace: production }
spec:
  selector: { app: authsys }
  ports: [{ port: 80, targetPort: 8001, name: http }]
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: { name: authsys, namespace: production }
spec:
  minAvailable: 2
  selector:
    matchLabels: { app: authsys }
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: { name: authsys, namespace: production }
spec:
  scaleTargetRef: { apiVersion: apps/v1, kind: Deployment, name: authsys }
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource: { name: cpu, target: { type: Utilization, averageUtilization: 70 } }
```

```bash
kubectl create namespace production
kubectl create secret generic authsys-secrets -n production \
  --from-literal=redis-password="$REDIS_PASSWORD" \
  --from-literal=encryption-key="$ENCRYPTION_KEY" \
  --from-file=jwt-private-key=jwt-private.b64 \
  --from-file=jwt-public-key=jwt-public.b64
kubectl create secret generic firebase-credentials -n production \
  --from-file=key.json=./firebase-service-account.json
kubectl apply -f k8s/ -n production
kubectl rollout status deployment/authsys -n production
```

### Rolling back

```bash
kubectl rollout undo deployment/authsys -n production      # Kubernetes
docker run ... authsys:<previous-tag>                       # Docker
```

Database changes are in Firestore documents, so keep new fields additive and backward compatible so an older version can still read them.

---

## Operations runbook

| Symptom | Likely cause | What to check |
|---------|--------------|---------------|
| Readiness failing | Redis or Firestore unreachable | `/actuator/health` components; network policy; `REDIS_PASSWORD` |
| Everyone gets 401 | Wrong or rotated JWT key; clock skew | Key pair matches across replicas; NTP on nodes |
| Spike in 429 | Real abuse, or a shared NAT/proxy IP | Gateway forwards the real client IP (`X-Forwarded-For`) |
| Emails not sent | Brevo key or unverified sender | `BREVO_*` variables; sender domain verified in Brevo |
| SMS OTP not arriving | Africa's Talking sandbox credentials | `AT_USERNAME` is not `sandbox` in production |
| Users stuck in `PENDING_VERIFICATION` | Verification link points at the wrong host | `APP_BASE_URL` is the public URL |
| Frequent logouts | Refresh reuse detection firing | `auth_token_reuse_detected_total`; client retrying refresh in parallel |

**Routine tasks**
- Rotate JWT signing keys every 30 days, keeping the old public key until old tokens expire
- Rotate `ENCRYPTION_KEY` with a re-encryption plan, because existing OTPs and temporary passwords use the old key
- Review failed-login and lockout metrics weekly
- Patch dependencies monthly; Spring Boot 3.2 is out of open-source support, so plan the upgrade to a supported 3.x line

---

## Development

```bash
mvn clean install                                   # build and unit test
mvn test                                            # unit tests
mvn verify -P integration-tests                     # integration tests
mvn jacoco:report                                   # coverage: target/site/jacoco/index.html
mvn spotless:apply                                  # format (Google Java Style)
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

Remote debugging:

```bash
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005"
```

Use `logging.level.com.techStack.authSys=DEBUG` locally only. Never enable debug logging for `org.springframework.security` in production, since it can include sensitive request details.

Target test coverage is 80% or higher.

---

## Contributing

1. Fork the repository and create a branch: `git checkout -b feature/short-description`
2. Make the change and add tests
3. Run `mvn spotless:apply verify`
4. Commit with a clear message, e.g. `feat: add device trust list`
5. Open a pull request

A pull request needs a passing pipeline, a maintainer review, tests for new behaviour, updated documentation, and no new security findings.

---

## License and support

Released under the [MIT License](LICENSE).

**Maintainer:** Fixtone Kaloki · fixtone94tec@gmail.com · [@94tec](https://github.com/94tec)

- Bugs and feature requests: open an issue on the repository
- Security issues: email the maintainer directly (do not open a public issue)
- Questions: use the repository's Discussions