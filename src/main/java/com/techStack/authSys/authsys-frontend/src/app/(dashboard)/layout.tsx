"use client";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { useAuthStore } from "@/store/auth-store";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const accessToken = useAuthStore((s) => s.accessToken);
  const redirected = useRef(false);

  const [hasHydrated, setHasHydrated] = useState(useAuthStore.persist.hasHydrated());

  useEffect(() => {
    const unsub = useAuthStore.persist.onFinishHydration(() => setHasHydrated(true));
    setHasHydrated(useAuthStore.persist.hasHydrated());
    return unsub;
  }, []);

  useEffect(() => {
    if (!hasHydrated) return;

    if (!isAuthenticated || !accessToken) {
      // Don't trust the very first unauthenticated reading right after
      // hydration flips true — give the store one more tick to actually
      // apply the rehydrated state before deciding to redirect.
      const timeout = setTimeout(() => {
        const stillUnauthed =
            !useAuthStore.getState().isAuthenticated || !useAuthStore.getState().accessToken;
        if (stillUnauthed && !redirected.current) {
          redirected.current = true;
          router.replace("/login");
        }
      }, 0);
      return () => clearTimeout(timeout);
    }

    if (
        typeof document !== "undefined" &&
        !document.cookie.includes("authsys-has-session")
    ) {
      document.cookie = [
        "authsys-has-session=1",
        "path=/",
        "SameSite=Strict",
        "Max-Age=86400",
      ].join("; ");
    }
  }, [hasHydrated, isAuthenticated, accessToken, router]);

  if (!hasHydrated || !isAuthenticated || !accessToken) {
    return (
        <div className="flex min-h-screen items-center justify-center bg-background">
          <div className="flex items-center gap-3 text-muted-foreground">
            <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <span className="text-sm">Checking session…</span>
          </div>
        </div>
    );
  }

  return (
      <div className="flex min-h-screen bg-background">
        <Sidebar />
        <div className="flex flex-1 flex-col overflow-hidden">
          <Topbar />
          <main className="flex-1 overflow-y-auto p-6 lg:p-8">{children}</main>
        </div>
      </div>
  );
}