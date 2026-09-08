import { NextResponse, type NextRequest } from "next/server";

/**
 * damuchi-ops-frontend middleware
 *
 * Auth is handled entirely by authsys-frontend (port 3000).
 * This app has no login/register pages of its own.
 *
 * Unauthenticated flow:
 *   1. User hits a protected route
 *   2. Middleware redirects to /login-redirect?to=<intended path>
 *   3. LoginRedirectPage saves intended path to sessionStorage,
 *      then sends user to authsys-frontend/login?redirect=<callback URL>
 *   4. After login, authsys-frontend redirects to /auth-callback#token=...
 *   5. AuthCallbackPage writes the local session and sends user to their
 *      intended destination (or role-based default)
 */

// Public paths — accessible without a session.
// Note: NO /login or /register here — those live on authsys-frontend.
const PUBLIC_PATHS = [
  "/tours",
  "/safaris",
  "/destinations",
  "/hotels",
  "/experiences",
  "/plan-your-trip",
  "/about",
  "/contact",
  "/enquiry",
  "/support",
  "/whatsapp",
  "/testimonials",
  "/sustainability",
  "/faq",
  "/travel-guide",
  "/best-time-to-visit",
  "/packing-list",
  "/travel-insurance",
  "/visa-information",
  "/login-redirect",
  "/auth-callback",
  "/login-required",
  "/registration-submitted",
  "/pending-approval",
];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // ── 1. Always pass through Next.js internals and static files ────────────
  if (
    pathname.startsWith("/_next/") ||
    pathname.startsWith("/api/") ||
    pathname === "/favicon.ico" ||
    pathname === "/robots.txt" ||
    pathname === "/site.webmanifest" ||
    /\.(png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf|otf|css|js|map)(\?.*)?$/.test(pathname)
  ) {
    return NextResponse.next();
  }

  // ── 2. Root → pass through (app/page.tsx redirects to /tours) ───────────
  if (pathname === "/") return NextResponse.next();

  // ── 3. Public paths — always accessible ──────────────────────────────────
  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"))) {
    return NextResponse.next();
  }

  // ── 4. Protected routes — check session cookie ────────────────────────────
  const sessionCookie = request.cookies.get("authsys-has-session");

  if (!sessionCookie?.value) {
    // Bounce through client-side page so we can write sessionStorage
    // (middleware runs on the edge — no access to sessionStorage directly)
    const bounceUrl = new URL("/login-redirect", request.url);
    bounceUrl.searchParams.set("to", pathname);
    const response = NextResponse.redirect(bounceUrl);
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|_next/data|_next/webpack|api|favicon\\.ico|robots\\.txt|site\\.webmanifest).*)",
  ],
};
