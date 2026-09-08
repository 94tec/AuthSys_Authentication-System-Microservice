import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type {Role, TokenPair, User } from "@/types/index-types";

// ─────────────────────────────────────────────────────────────────
// Cookie helpers
// Using Max-Age=86400 (24h) makes the cookie persist across tabs
// and is immediately visible to the server on the next navigation,
// whereas a session cookie (no Max-Age) can sometimes not be sent
// when the navigation happens in the same rAF frame as the write.
// ─────────────────────────────────────────────────────────────────
function writeSessionCookie() {
    if (typeof document === "undefined") return;
    document.cookie = [
        "authsys-has-session=1",
        "path=/",
        "SameSite=Strict",
        "Max-Age=86400", // 24 hours — matches typical refresh token window
    ].join("; ");
}

function clearSessionCookie() {
    if (typeof document === "undefined") return;
    document.cookie = [
        "authsys-has-session=",
        "path=/",
        "SameSite=Strict",
        "Max-Age=0",     // Expire immediately
        "expires=Thu, 01 Jan 1970 00:00:00 GMT",
    ].join("; ");
}

interface AuthState {
    accessToken: string | null;
    refreshToken: string | null;
    user: Partial<User> | null;
    tempToken: string | null;
    isAuthenticated: boolean;

    setTokens: (t: TokenPair) => void;
    setUser: (u: Partial<User>) => void;
    setTempToken: (t: string | null) => void;
    clearSession: () => void;

    hasRole: (role: Role) => boolean;
    isAdmin: () => boolean;
    isSuperAdmin: () => boolean;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set, get) => ({
            accessToken: null,
            refreshToken: null,
            user: null,
            tempToken: null,
            isAuthenticated: false,

            setTokens: (tokens) => {
                // Write cookie FIRST, then update state.
                // The rAF+setTimeout in safeNavigate() gives enough time for
                // the cookie to be committed before the navigation request fires.
                writeSessionCookie();
                set({
                    accessToken: tokens.accessToken,
                    refreshToken: tokens.refreshToken,
                    isAuthenticated: true,
                    tempToken: null,
                });
            },

            setUser: (user) => set({ user }),

            setTempToken: (token) => set({ tempToken: token }),

            clearSession: () => {
                clearSessionCookie();
                set({
                    accessToken: null,
                    refreshToken: null,
                    user: null,
                    tempToken: null,
                    isAuthenticated: false,
                });
            },

            hasRole: (role) => get().user?.roles?.includes(role) ?? false,
            isAdmin: () => {
                const roles = get().user?.roles ?? [];
                return roles.includes("ADMIN") || roles.includes("SUPER_ADMIN");
            },
            isSuperAdmin: () => get().user?.roles?.includes("SUPER_ADMIN") ?? false,
        }),
        {
            name: "authsys-session",
            storage: createJSONStorage(() =>
                typeof window !== "undefined" ? sessionStorage : {
                    getItem: () => null,
                    setItem: () => {},
                    removeItem: () => {},
                }
            ),
            // Only persist tokens + user — tempToken is deliberately excluded
            // so it's cleared on tab close (it's a short-lived sensitive value)
            partialize: (s) => ({
                accessToken: s.accessToken,
                refreshToken: s.refreshToken,
                user: s.user,
                isAuthenticated: s.isAuthenticated,
            }),
        }
    )
);