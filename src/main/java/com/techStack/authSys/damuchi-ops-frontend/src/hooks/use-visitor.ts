"use client";

import { useEffect, useState } from "react";
import { useAuthStore } from "@/store/auth-store";

export type VisitorStatus = "loading" | "guest" | "customer" | "staff";

export interface Visitor {
    status: VisitorStatus;
    user: ReturnType<typeof useAuthStore.getState>["user"] | null;
}

const STAFF_ROLES = ["ADMIN", "MANAGER", "OPERATOR", "SUPER_ADMIN"];

function normalizeRoles(user: any): string[] {
    const roles: string[] = [];
    if (typeof user?.role === "string") roles.push(user.role);
    if (Array.isArray(user?.roles)) {
        for (const r of user.roles) {
            if (typeof r === "string") roles.push(r);
            else if (r?.name) roles.push(r.name);
            else if (r?.authority) roles.push(r.authority);
        }
    }
    return roles.map((r) => r.replace(/^ROLE_/, "").toUpperCase());
}

/**
 * Resolves the current visitor's status for personalizing public pages.
 *
 * Defaults to "loading" then settles to "guest" | "customer" | "staff"
 * once the persisted auth store has hydrated — mirrors the hasHydrated
 * pattern in the login page. Callers MUST treat "loading" as equivalent
 * to "guest" for anything rendered before hydration completes, so an
 * authenticated customer never causes a hydration mismatch and an
 * unauthenticated visitor is never shown customer-only content by a
 * race condition.
 */
export function useVisitor(): Visitor {
    const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
    const accessToken = useAuthStore((s) => s.accessToken);
    const user = useAuthStore((s) => s.user);

    const [hasHydrated, setHasHydrated] = useState(
        () => useAuthStore.persist.hasHydrated()
    );

    useEffect(() => {
        const unsub = useAuthStore.persist.onFinishHydration(() => setHasHydrated(true));
        setHasHydrated(useAuthStore.persist.hasHydrated());
        return unsub;
    }, []);

    if (!hasHydrated) return { status: "loading", user: null };
    if (!isAuthenticated || !accessToken) return { status: "guest", user: null };

    const roles = normalizeRoles(user);
    if (roles.some((r) => STAFF_ROLES.includes(r))) {
        return { status: "staff", user };
    }
    return { status: "customer", user };
}