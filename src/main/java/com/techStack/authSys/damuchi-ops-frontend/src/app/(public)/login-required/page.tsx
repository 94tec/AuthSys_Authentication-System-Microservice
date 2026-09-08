import Link from "next/link";
import { AlertCircle } from "lucide-react";

/**
 * LoginRequiredPage
 *
 * Shown when AuthCallbackPage receives a callback with no/invalid tokens.
 * This should be rare — it means the handoff from authsys-frontend failed
 * or the user navigated to /auth-callback directly without a fragment.
 */
export default function LoginRequiredPage() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="max-w-sm text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-red-50 text-red-500">
          <AlertCircle className="h-7 w-7" />
        </div>
        <h1 className="mt-5 font-display text-2xl font-bold text-earth">
          Session expired
        </h1>
        <p className="mt-2 text-sm text-stone">
          Your sign-in session couldn't be established. This can happen if
          you took too long on the login page or navigated here directly.
        </p>
        <div className="mt-6 h-0.5 w-12 bg-savanna mx-auto" />
        <Link
          href="/login-redirect"
          className="btn-primary mt-6 inline-flex"
        >
          Try signing in again
        </Link>
      </div>
    </div>
  );
}
