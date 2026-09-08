"use client";
import { useRouter } from "next/navigation";
import { LogOut, User as UserIcon, TrendingUpIcon } from "lucide-react";
import { toast } from "sonner";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";
import { useState } from "react";
import {NotificationBell} from "@/components/layout/notification-bell";

export function Topbar() {
  const router = useRouter();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const { user, isAdmin } = useAuthStore();
  const admin = isAdmin();

  const clearSession = useAuthStore((state) => state.clearSession);

  const AUTH_FRONTEND_URL = process.env.NEXT_PUBLIC_AUTH_FRONTEND_URL ?? "http://localhost:3000";

  const displayName = user?.displayName || user?.email || "Account";

  const initials = user?.displayName
      ? user.displayName
          .split(" ")
          .filter(Boolean)
          .map((p: string) => p[0])
          .slice(0, 2)
          .join("")
          .toUpperCase()
      : user?.email?.[0]?.toUpperCase() ?? "?";

  async function handleLogout() {
    if (isLoggingOut) return;
    setIsLoggingOut(true);

    try {
      await authApi.logout();
    } catch {
      // ignore
    }

    try {
      clearSession();
    } catch {
      // ignore — proceed with logout regardless of local cleanup failure
    }

    toast.success("Signed out"); // show feedback before redirect

    const logoutUrl = new URL(`${AUTH_FRONTEND_URL}/logout`);
    logoutUrl.searchParams.set("next", `${AUTH_FRONTEND_URL}/`);
    window.location.href = logoutUrl.toString();
    // No need to reset isLoggingOut – page will unload
  }

  return (
      <header className="flex h-16 items-center justify-between border-b border-border bg-background px-5 lg:px-8">
        {/* Left side: breadcrumb-ready slot */}
        <div className="flex items-center gap-2">
          {admin && (
              <Badge variant="secondary" className="hidden text-[10px] sm:inline-flex">
                {user?.roles?.includes("SUPER_ADMIN") ? "Super Admin" : "Admin"}
              </Badge>
          )}
        </div>

        {/* Right side: notifications + user menu */}
        <div className="flex items-center gap-2">
          <NotificationBell />
          <DropdownMenu>
            <DropdownMenuTrigger className="flex items-center gap-2 rounded-lg p-1 outline-none focus-visible:ring-2 focus-visible:ring-ring">
              <Avatar className="h-8 w-8">
                <AvatarFallback className="text-xs">{initials}</AvatarFallback>
              </Avatar>
              <span className="hidden text-sm font-medium sm:block">
              {displayName}
            </span>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>
                <p className="font-medium text-foreground">
                  {displayName}
                </p>
                <p className="mt-0.5 truncate text-xs text-muted-foreground">{user?.email}</p>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {user?.roles?.map((r: string) => (
                      <span key={r} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                    {r}
                  </span>
                  ))}
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => router.push("/profile")}>
                <UserIcon className="h-4 w-4" />
                My profile
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => router.push("/revenue")}>
                <TrendingUpIcon className="h-4 w-4" />
                Revenue
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                  onSelect={handleLogout}
                  className="text-destructive focus:bg-destructive/10 focus:text-destructive"
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>
  );
}