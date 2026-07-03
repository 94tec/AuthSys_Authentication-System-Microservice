"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Compass,
  LayoutDashboard,
  Map,
  Users,
  ShieldCheck,
  Settings,
  FileText,
  Key,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/store/auth-store";

interface NavItem {
  href: string;
  label: string;
  icon: React.ElementType;
  adminOnly?: boolean;
  superAdminOnly?: boolean;
  exact?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard, exact: true },
  { href: "/tours", label: "Tours", icon: Map },
  { href: "/profile", label: "My Profile", icon: User },
  { href: "/admin/pending", label: "Approvals", icon: ShieldCheck, adminOnly: true },
  { href: "/admin/users", label: "Team", icon: Users, adminOnly: true },
  { href: "/admin/roles", label: "Roles & Permissions", icon: Key, adminOnly: true },
  { href: "/admin/audit", label: "Audit Log", icon: FileText, adminOnly: true },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { isAdmin, isSuperAdmin } = useAuthStore();
  const admin = isAdmin();

  const items = NAV_ITEMS.filter((item) => {
    if (item.superAdminOnly) return isSuperAdmin();
    if (item.adminOnly) return admin;
    return true;
  });

  return (
    <aside className="hidden w-64 flex-col border-r border-border bg-card lg:flex">
      {/* Logo */}
      <div className="flex h-16 items-center gap-2.5 border-b border-border px-6">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-expedition-forest">
          <Compass className="h-4 w-4 text-expedition-clay" strokeWidth={1.75} />
        </div>
        <div>
          <p className="font-display text-sm font-medium leading-tight">Basecamp</p>
          <p className="font-mono text-[10px] text-muted-foreground">
            {admin ? (isSuperAdmin() ? "Super Admin" : "Admin") : "Staff Portal"}
          </p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 p-3">
        {items.map((item) => {
          const isActive = item.exact
            ? pathname === item.href
            : pathname.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors duration-100",
                isActive
                  ? "bg-accent/10 text-accent"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              <Icon
                className={cn(
                  "h-4 w-4",
                  isActive ? "text-accent" : "text-muted-foreground"
                )}
                strokeWidth={1.75}
              />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border p-4">
        <p className="font-mono text-[10px] text-muted-foreground/60">
          Port 8001 · authSys v1.0
        </p>
      </div>
    </aside>
  );
}
