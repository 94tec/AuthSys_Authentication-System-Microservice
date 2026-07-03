# Venture Tours — Staff Auth Portal

Next.js 14 (App Router) + TypeScript + Tailwind + shadcn/ui auth system for the Venture Tours staff portal.

## Stack

- **Framework**: Next.js 14 App Router
- **Language**: TypeScript (strict)
- **Styling**: Tailwind CSS + custom expedition design tokens
- **Components**: shadcn/ui primitives (Radix-based)
- **State**: Zustand (persisted to `sessionStorage` — not `localStorage`, for security)
- **Forms**: React Hook Form + Zod
- **HTTP**: Axios with automatic JWT refresh + error normalisation
- **Notifications**: Sonner

## Design System — Expedition Palette

| Token       | Hex       | Use                        |
|-------------|-----------|----------------------------|
| Forest      | `#0B1F1A` | Primary / background dark  |
| Sand        | `#F5F1E8` | Background light / surface |
| Clay        | `#C9742F` | CTAs / accents             |
| Moss        | `#3D5A4C` | Secondary actions / badges |
| Rust        | `#8B2E2E` | Errors / destructive       |

## Auth Flows

| Route                          | Description                                 |
|--------------------------------|---------------------------------------------|
| `/login`                       | Email + password login                      |
| `/verify-otp`                  | 2FA OTP for regular login                   |
| `/register`                    | Staff registration request                  |
| `/register-submitted`          | Post-registration confirmation              |
| `/pending-approval`            | Account awaiting admin approval             |
| `/first-time-setup/step-1`     | Change temporary password                   |
| `/first-time-setup/step-2`     | OTP verification during setup               |
| `/first-time-setup/step-3`     | Setup complete — passport stamp moment      |
| `/forgot-password`             | Request reset link (email-safe, no leakage) |
| `/reset-password?token=…`      | Set new password via token from email       |

## Dashboard

| Route                               | Access            |
|-------------------------------------|-------------------|
| `/dashboard`                        | All roles         |
| `/dashboard/admin/pending-approvals`| ADMIN only        |
| `/dashboard/tours`                  | All roles         |
| `/dashboard/settings`               | All roles         |

## Getting Started

```bash
cp .env.local.example .env.local
# edit NEXT_PUBLIC_API_URL to point at your backend

npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Security Notes

- JWT access tokens stored in `sessionStorage` (cleared on tab close)
- Route protection via Next.js middleware (`auth-token` cookie, set on login, cleared on logout)
- Forgot-password flow never reveals whether an email is registered
- Refresh token rotation handled automatically by Axios interceptor
- All forms validated client-side with Zod matching backend `PasswordPolicyService` rules

## Project Structure

```
src/
├── app/
│   ├── (auth)/          # Public auth pages
│   └── (dashboard)/     # Protected dashboard pages
├── components/
│   ├── auth/            # OTP input, trail steps, passport stamp, password strength
│   ├── dashboard/       # Sidebar, topbar, approval card
│   ├── layout/          # Auth layout wrapper
│   └── ui/              # shadcn/ui primitives
├── lib/
│   ├── api/             # Axios client + service modules
│   ├── stores/          # Zustand auth store
│   └── validations/     # Zod schemas
└── types/               # Shared TypeScript types
```
