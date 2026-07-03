import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

const PUBLIC_PATHS = [
  "/login",
  "/register",
  "/register-submitted",
  "/pending-approval",
  "/forgot-password",
  "/reset-password",
  "/verify-otp",
  "/first-time-setup",
]

const ADMIN_PATHS = ["/admin"]

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  const token = request.cookies.get("auth-token")?.value

  const isPublic = PUBLIC_PATHS.some((p) => pathname.startsWith(p))
  const isAdmin  = ADMIN_PATHS.some((p) => pathname.startsWith(p))
  const isDashboard = pathname.startsWith("/dashboard") || isAdmin

  // Redirect unauthenticated users away from protected routes
  if (isDashboard && !token) {
    const url = request.nextUrl.clone()
    url.pathname = "/login"
    url.searchParams.set("callbackUrl", pathname)
    return NextResponse.redirect(url)
  }

  // Redirect authenticated users away from auth pages
  if (isPublic && token && pathname !== "/pending-approval") {
    const url = request.nextUrl.clone()
    url.pathname = "/dashboard"
    return NextResponse.redirect(url)
  }

  return NextResponse.next()
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|api).*)"],
}
