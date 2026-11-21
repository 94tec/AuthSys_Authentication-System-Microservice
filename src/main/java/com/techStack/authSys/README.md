# Damuchi Tours — Full-Stack Platform

Damuchi Tours is a tour-management and staff-operations platform built with a Spring Boot backend and two separate frontend applications:

- **AuthSys Frontend** — authentication, onboarding, user administration, roles, permissions, and audit visibility.
- **Damuchi Ops Frontend** — operational dashboard for managing tours, availability, bookings, customers, and related business workflows.

The repository is organised as a monorepo so the backend and both frontend applications can be developed, versioned, and deployed from one codebase.

## Repository Structure

```text
Damuchi_tours/
├── authsys-frontend/          # Authentication and staff portal frontend
├── damuchi-ops-frontend/      # Damuchi Tours operations frontend
├── tour/                      # Spring Boot AuthSys backend
└── README.md                  # This file
```

## Technology Overview

| Area | Technology |
|---|---|
| Frontend framework | Next.js 14, App Router, TypeScript |
| UI | Tailwind CSS, shadcn/ui, Radix UI primitives |
| Forms and validation | React Hook Form, Zod |
| State management | Zustand |
| HTTP client | Axios |
| Notifications | Sonner |
| Icons | Lucide React |
| Backend | Java 21, Spring Boot, Spring WebFlux/Netty |
| Relational database | PostgreSQL |
| Migrations | Flyway |
| Document database | Firebase Firestore |
| Authentication | Firebase Authentication |
| Cache and sessions | Redis |
| Email | Brevo |
| SMS / OTP | Africa’s Talking |
| Frontend hosting | Vercel |
| Backend hosting | Render |
| Version control | Git and GitHub |

## Applications

### AuthSys Frontend

The AuthSys frontend is the secure entry point for staff and administrators. It handles:

- User registration and approval workflow
- Login and multi-factor OTP verification
- First-time password setup
- Password reset
- User profile and password management
- Pending-user approval and rejection
- User account locking and unlocking
- Role and permission administration
- Audit-log visibility
- System settings

It runs locally on port `3000`.

### Damuchi Ops Frontend

The Damuchi Ops frontend is the operational workspace for managing the tour business. It provides interfaces for:

- Tour management
- Tour availability
- Bookings and customer-related workflows
- Operational dashboards
- Staff-facing business operations
- Future modules such as payments, fleet, guides, customers, and reporting

It runs locally on port `3001`.

## Backend Overview

The backend is a Java 21 Spring Boot application located in the `tour/` directory.

Key backend capabilities include:

- JWT-based authentication and session handling
- Firebase Authentication integration
- Firestore-backed permissions, ACLs, and role-permission mappings
- PostgreSQL-backed business data
- Flyway-managed database migrations
- Redis caching, session records, rate limiting, and blacklist cleanup
- Brevo email notifications
- Africa’s Talking SMS OTP delivery
- Role-based access control with seeded roles and permissions
- Actuator health endpoints

The backend uses a reactive Netty/WebFlux server and currently runs locally on port `8001`.

## Local Development

### Prerequisites

Install the following before starting:

- Node.js 18 or later
- npm 9 or later
- Java 21
- Maven
- PostgreSQL 14 or later
- Redis 6 or later
- Firebase project credentials
- Brevo API credentials
- Africa’s Talking credentials, if SMS OTP is required

### Start the Backend

From the `tour/` directory:

```bash
./mvnw spring-boot:run
```

Ensure the local backend is running on:

```text
http://localhost:8001
```

### Start AuthSys Frontend

From the repository root:

```bash
cd authsys-frontend
npm install
cp .env.local.example .env.local
npm run dev
```

Open:

```text
http://localhost:3000
```

### Start Damuchi Ops Frontend

From the repository root:

```bash
cd damuchi-ops-frontend
npm install
cp .env.local.example .env.local
npm run dev
```

Open:

```text
http://localhost:3001
```

## Environment Variables

Each frontend has its own `.env.local` file. Never commit real secrets, API keys, Firebase service-account files, database credentials, or JWT secrets to GitHub.

### AuthSys Frontend

Create `authsys-frontend/.env.local`:

```env
VITE_API_BASE_URL=http://localhost:8001
```

If the project uses Next.js server-side environment variables instead, use:

```env
NEXT_PUBLIC_API_URL=http://localhost:8001
```

### Damuchi Ops Frontend

Create `damuchi-ops-frontend/.env.local`:

```env
VITE_API_BASE_URL=http://localhost:8001
```

If the project uses Next.js server-side environment variables instead, use:

```env
NEXT_PUBLIC_API_URL=http://localhost:8001
```

## Production Deployment

### Frontend Hosting

Both frontend applications are deployed independently to Vercel.

| Application | Production domain | Vercel root directory |
|---|---|---|
| AuthSys Frontend | `https://auth.kivanasafaris.com` | `authsys-frontend` |
| Damuchi Ops Frontend | `https://www.kivanasafaris.com` | `damuchi-ops-frontend` |

Because both applications are in one repository, create two separate Vercel projects and set the appropriate **Root Directory** for each.

### Backend Hosting

The Spring Boot backend is deployed to Render.

| Service | Production domain |
|---|---|
| AuthSys API | `https://api.kivanasafaris.com` |

The backend requires managed PostgreSQL, Redis, Firebase credentials, Brevo credentials, and secure environment variables in Render.

### DNS Records

The following DNS structure is recommended:

| Type | Name | Target | Purpose |
|---|---|---|---|
| CNAME | `auth` | Vercel-provided target | AuthSys frontend |
| CNAME | `www` | Vercel-provided target | Damuchi Ops frontend |
| CNAME | `api` | Render-provided target | Spring Boot API |

Do not modify existing MX, SPF, DKIM, DMARC, or other email-related DNS records when adding website records.

## Security Practices

- Store all secrets in Vercel and Render environment variables.
- Never commit `.env`, `.env.local`, Firebase service-account JSON, API keys, database passwords, or JWT secrets.
- Use HTTPS for all production traffic.
- Restrict CORS to approved frontend origins only.
- Keep access tokens in browser session storage and rely on the backend for real authorisation.
- Protect administrative routes through both frontend route guards and backend role checks.
- Do not expose Actuator endpoints publicly except the health endpoint required for monitoring.
- Enable database backups and test restore procedures before production launch.
- Rotate JWT secrets, encryption keys, and API keys if they are ever exposed.

## Recommended CORS Configuration

The backend should allow only the production frontend origins:

```text
[https://auth.kivanasafaris.com,[https://ops.kivanasafaris.com](https://ops.kivanasafaris.com)](https://auth.kivanasafaris.com,[https://ops.kivanasafaris.com](https://ops.kivanasafaris.com))
```

During local development, include the local frontend origins if needed:

```text
http://localhost:3000,http://localhost:3001
```

## Deployment Checklist

- [ ] Backend deployed to Render
- [ ] PostgreSQL connected
- [ ] Redis connected
- [ ] Firebase service account configured securely
- [ ] Brevo API configured
- [ ] JWT and encryption secrets configured
- [ ] `/actuator/health` returns `UP`
- [ ] AuthSys frontend deployed to Vercel
- [ ] Damuchi Ops frontend deployed to Vercel
- [ ] Custom domains added to Vercel and Render
- [ ] DNS records created in Cloudflare
- [ ] HTTPS certificates verified
- [ ] CORS configured for production frontend domains
- [ ] Login, registration, password reset, OTP, tours, and admin workflows tested
- [ ] Local development still uses local services and credentials

## Support

For technical issues, contact:

**Fixtone Kaloki**  
Software Developer & ICT Specialist  
Email: fixtone94tec@gmail.com
Phone: +254711274834