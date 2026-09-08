/**
 * auth-redirect-utils.ts  (damuchi-ops-frontend)
 *
 * Local copy of the same-origin redirect guard from authsys-frontend.
 * Kept as a plain string-shape check (no origin comparison) so it's safe
 * to use identically in either app — see authsys-frontend's version for
 * the full cross-origin handoff utilities this app doesn't need.
 */

/**
 * Returns true if the redirect is a safe same-origin path
 * (starts with / but not //).
 */
export function isSameOriginRedirect(redirectUrl: string): boolean {
    return (
        typeof redirectUrl === "string" &&
        redirectUrl.startsWith("/") &&
        !redirectUrl.startsWith("//")
    );
}