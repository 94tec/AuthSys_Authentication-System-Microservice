"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    Compass,
    LayoutDashboard,
    Map,
    CalendarCheck,
    Users2,
    Settings,
    Inbox,
    LucideHome,
    House,
    ClockAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/store/auth-store";

interface NavItem {
    href: string;
    label: string;
    icon: React.ElementType;
    adminOnly?: boolean;
    exact?: boolean;
}

const NAV_ITEMS: NavItem[] = [
    { href: "/dashboard", label: "Overview", icon: LayoutDashboard, exact: true },
    { href: "/enquiries", label: "Enquiries", icon: Inbox, adminOnly: true },
    { href: "/tours", label: "Tour catalogue", icon: Map, adminOnly: true },
    { href: "/bookings", label: "Bookings", icon: CalendarCheck },
    { href: "/customers", label: "Customers", icon: Users2, adminOnly: true },
    { href: "/settings", label: "Settings", icon: Settings, adminOnly: true },
    { href: "/availability", label: "Availability", icon: ClockAlert, adminOnly: true },
];

export function Sidebar() {
    const pathname = usePathname();
    const isAdmin = useAuthStore((s) => s.isAdmin)();
    const user = useAuthStore((s) => s.user);
    const items = NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin);

    const fullName = user?.displayName ?? "";

    return (
        <aside className="hidden w-64 flex-col border-r border-border bg-card lg:flex">
            {/* Logo */}
            <div className="flex h-16 items-center gap-2.5 border-b border-border px-6">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-expedition-forest">
                    <Compass className="h-4 w-4 text-expedition-clay" strokeWidth={1.75} />
                </div>
                <div>
                    <p className="font-display text-sm font-medium leading-tight">Damuchi Safaris</p>
                    <p className="font-mono text-[10px] text-muted-foreground">
                        {isAdmin ? "Tour Operations" : "Staff Portal"}
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
                                className={cn("h-4 w-4", isActive ? "text-accent" : "text-muted-foreground")}
                                strokeWidth={1.75}
                            />
                            {item.label}
                        </Link>
                    );
                })}
            </nav>

            {/* User footer */}
            <div className="border-t border-border p-4">
                <p className="truncate text-xs font-medium leading-tight">
                    {fullName || user?.email || "Signed in"}
                </p>
                <p className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
                    {user?.email ?? ""}
                </p>
            </div>
        </aside>
    );
}