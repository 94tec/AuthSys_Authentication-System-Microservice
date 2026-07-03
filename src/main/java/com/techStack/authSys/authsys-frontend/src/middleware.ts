import { NextResponse, type NextRequest } from "next/server";

// ─────────────────────────────────────────────────────────────────
// Auth-gating middleware
//
// How the cookie/navigation flow works:
//   1. User logs in → authApi.login() → server returns tokens
//   2. setTokens() writes document.cookie (client-side, synchronous)
//   3. safeNavigate() uses rAF+setTimeout to delay navigation until
//      the cookie is committed to the browser's cookie store
//   4. Browser sends navigation request WITH cookie in headers
//   5. This middleware reads the cookie and allows access
//
// Fallback: if cookie is somehow not present (storage blocked, etc.),
// the dashboard layout itself also checks Zustand state (sessionStorage)
// and handles the redirect client-side instead.
// ─────────────────────────────────────────────────────────────────

const PUBLIC_PATHS = [
  "/login",
  "/landing",
  "/register",
  "/forgot-password",
  "/reset-password",
  "/registration-submitted",
  "/pending-approval",
];

const SETUP_PATHS = [
  "/setup",       // /setup/password, /setup/verify, /setup/complete
  "/login/verify",
];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // ── 1. Always pass through Next.js internals and static files ──
  // This is the root cause of the "MIME type 'text/html'" error:
  // if these are intercepted they get redirected to /login (HTML).
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

  // ── 2. Root → always allow (page.tsx will redirect to /login) ──
  if (pathname === "/app") {
    return NextResponse.next();
  }

  // ── 3. Public routes — always accessible ──
  if (PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(p + "/"))) {
    return NextResponse.next();
  }

  // ── 4. First-time setup & OTP routes — no full session needed ──
  if (SETUP_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // ── 5. Protected routes — check session cookie ──
  const sessionCookie = request.cookies.get("authsys-has-session");

  if (!sessionCookie?.value) {
    // Preserve the intended destination so login can redirect back
    const landingUrl = new URL("/app", request.url);
    landingUrl.searchParams.set("redirect", pathname);

    const response = NextResponse.redirect(landingUrl);

    // Tell the browser not to cache this redirect —
    // important so a stale redirect doesn't loop after login
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  return NextResponse.next();
}

export const config = {
  // Exclude _next/static, _next/image, api, and common static extensions
  // at the matcher level as a first line of defence.
  // The runtime check above is a second layer for edge cases.
  matcher: [
    "/((?!_next/static|_next/image|_next/data|_next/webpack|api|favicon\\.ico|robots\\.txt|site\\.webmanifest).*)",
  ],
};