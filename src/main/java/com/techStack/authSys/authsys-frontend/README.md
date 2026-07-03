# authSys Frontend — Basecamp Staff Portal

Next.js 14 + TypeScript + Tailwind CSS + shadcn/ui frontend for the **authSys** Tour ERP SaaS.

## Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 14 (App Router, TypeScript) |
| Styling | Tailwind CSS + shadcn/ui (Radix UI primitives) |
| Forms | react-hook-form + Zod |
| State | Zustand (sessionStorage-persisted) |
| HTTP | Axios with JWT interceptor + auto-refresh |
| Notifications | Sonner toast |
| Icons | Lucide React |
| Fonts | Fraunces (display) · Inter (body) · JetBrains Mono (code) |

## Backend facts (from startup log)

- **Port**: 8001 (Netty/WebFlux reactive — not servlet)
- **Auth**: Firebase Auth · project `spring-data-a3ebb`
- **Documents**: Firestore (users, permissions, ACL, role-permissions)
- **Relational**: PostgreSQL via HikariPool (tours, `idx_tour_slug` constraint)
- **Cache**: Redis `localhost:6379` · 2s command timeout
- **Email**: Brevo (primary) · Gmail SMTP (secondary)
- **SMS**: Africa's Talking (OTP delivery for Kenya +254 numbers)
- **Roles seeded**: SUPER_ADMIN(27), ADMIN(27), MANAGER(14), DESIGNER(11), USER(7), GUEST(1)

## Setup

```bash
npm install
cp .env.local.example .env.local   # or use .env.local already provided
npm run dev
```

Open http://localhost:3000

## Pages

### Auth (public)
| Route | Maps to |
|---|---|
| `/login` | `AuthController.login` + `GoogleAuthController` |
| `/register` | `AuthController.registerUser` → PENDING_APPROVAL |
| `/registration-submitted` | Post-registration confirmation |
| `/pending-approval` | Shown when status = PENDING_APPROVAL |
| `/forgot-password` | `PasswordResetController.forgotPassword` |
| `/reset-password?token=` | `PasswordResetController.resetPassword` |
| `/login/verify` | `OtpController` (login 2FA) |
| `/setup/password` | `FirstTimeSetupController` Step 1 |
| `/setup/verify` | `FirstTimeSetupController` Step 2 |
| `/setup/complete` | `FirstTimeSetupController` Step 3 |

### Dashboard (authenticated)
| Route | Maps to |
|---|---|
| `/dashboard` | Overview with live stats |
| `/tours` | `TourController` — full CRUD |
| `/profile` | `UserProfileController` + `PasswordManagementController` |
| `/settings` | System info from startup log |
| `/admin/pending` | `AdminController.getPendingUsers` → approve/reject |
| `/admin/users` | `AdminController.getAllUsers` → lock/unlock |
| `/admin/roles` | `AdminRolePermissionController` — 6 roles, 27 permissions |
| `/admin/audit` | `AuditLogController.getAuditLogs` |

## Auth flow (First-time login — 3 steps)

```
POST /auth/login → { status: "FIRST_TIME_LOGIN", tempToken }
  ↓
POST /auth/first-time/change-password (X-Temp-Token) → OtpResult { sent, otp via SMS }
  ↓
POST /auth/first-time/verify-otp (X-Temp-Token) → OtpVerificationResult { verificationToken }
  ↓
POST /auth/first-time/complete { verificationToken } → TokenPair
```

## Security notes

- Access tokens live in `sessionStorage` (cleared on tab close)
- A lightweight non-sensitive `authsys-has-session=1` cookie is set for Next.js middleware route gating only
- The API itself enforces auth — the middleware is UX-only
- Forgot-password always returns success (prevents email enumeration)
- OTP digit input auto-submits on 6th digit — no submit button tap required

## Next SaaS modules (your roadmap)

Per the architecture discussion, add these next to the Spring Boot monolith:

1. **Organizations** — `organization_id UUID` on every business table
2. **Customers** — CRM (passport, preferences, booking history)
3. **Bookings** — Draft → Pending → Confirmed → Paid → Completed
4. **Payments** — M-Pesa, card, cash (Africa's Talking already wired for SMS notifications)
5. **Fleet** — Vehicles, drivers, maintenance
6. **Guides** — Availability, certifications, ratings

Each adds a new sidebar nav item and follows the same `lib/xxx-api.ts` → page pattern.
