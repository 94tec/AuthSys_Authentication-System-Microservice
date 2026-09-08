"use client";

import { useEffect } from "react";
import { useSearchParams } from "next/navigation";

const AUTH_FRONTEND_URL =
  process.env.NEXT_PUBLIC_AUTH_FRONTEND_URL ?? "http://localhost:3000";

const APP_URL =
  process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3001";

/**
 * LoginRedirectPage
 *
 * Thin client-side bounce page. Middleware can't write to sessionStorage
 * (it runs server-side on the edge), so it redirects here first.
 *
 * This page:
 *   1. Saves the intended destination to sessionStorage
 *      (AuthCallbackPage reads it after login completes)
 *   2. Redirects to authsys-frontend/login with a ?redirect= param
 *      pointing back to /auth-callback on this app
 *
 * Why not redirect directly from middleware to authsys-frontend?
 *   Because we'd lose the "intended path" — the user would always land
 *   on the default post-login page instead of where they were going.
 *   sessionStorage bridges that gap client-side.
 */
export default function LoginRedirectPage() {
  const searchParams = useSearchParams();
  const to = searchParams.get("to") ?? "/";

  useEffect(() => {
    // 1. Persist the intended destination — AuthCallbackPage will read this
    if (to && to !== "/login-redirect") {
      sessionStorage.setItem("damuchi-intended-path", to);
    }

    // 2. Build the authsys-frontend login URL with our callback as the
    //    ?redirect= param. authsys-frontend will validate this against
    //    its TRUSTED_REDIRECT_ORIGINS list before appending tokens.
    const callbackUrl = `${APP_URL}/auth-callback`;
    const loginUrl    = new URL(`${AUTH_FRONTEND_URL}/login`);
    loginUrl.searchParams.set("redirect", callbackUrl);

    window.location.href = loginUrl.toString();
  }, [to]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-dust">
      <div className="flex flex-col items-center gap-4">
        <div className="flex items-center gap-3">
          <svg className="h-5 w-5 animate-spin text-savanna" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
          </svg>
          <span className="text-sm font-medium text-earth">Redirecting to sign in…</span>
        </div>
        <p className="text-xs text-stone">
          You'll be taken to the Damuchi sign-in page.
        </p>
      </div>
    </div>
  );
}
