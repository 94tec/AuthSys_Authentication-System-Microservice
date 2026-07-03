"use client";

import { useRouter } from "next/navigation";
import { LogOut, User as UserIcon, Settings, Bell } from "lucide-react";
import { toast } from "sonner";

import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";

export function Topbar() {
  const router = useRouter();
  const { user, clearSession, isAdmin } = useAuthStore();
  const admin = isAdmin();

  const initials = user
    ? `${user.firstName?.[0] ?? ""}${user.lastName?.[0] ?? ""}`.toUpperCase()
    : "?";

  async function handleLogout() {
    try { await authApi.logout(); } catch { /* proceed */ }
    clearSession();
    toast.success("Signed out");
    router.push("/login");
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
        <button
          className="flex h-9 w-9 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          aria-label="Notifications"
        >
          <Bell className="h-4 w-4" />
        </button>

        <DropdownMenu>
          <DropdownMenuTrigger className="flex items-center gap-2 rounded-lg p-1 outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <Avatar className="h-8 w-8">
              <AvatarFallback className="text-xs">{initials}</AvatarFallback>
            </Avatar>
            <span className="hidden text-sm font-medium sm:block">
              {user?.firstName}
            </span>
          </DropdownMenuTrigger>

          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>
              <p className="font-medium text-foreground">
                {user?.firstName} {user?.lastName}
              </p>
              <p className="mt-0.5 truncate text-xs text-muted-foreground">{user?.email}</p>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {user?.roles?.map((r) => (
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
            <DropdownMenuItem onSelect={() => router.push("/settings")}>
              <Settings className="h-4 w-4" />
              Settings
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
