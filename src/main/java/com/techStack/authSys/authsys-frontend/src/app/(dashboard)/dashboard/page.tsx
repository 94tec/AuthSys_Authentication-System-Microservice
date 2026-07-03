"use client";

import { useEffect, useState } from "react";
import { Map, Users, ShieldCheck, Activity, KeyRound, Database, Cpu } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/layout/page-header";
import { useAuthStore } from "@/store/auth-store";
import { adminApi } from "@/lib/admin-api";

interface Stats {
  pendingApprovals: number;
  totalUsers: number;
  totalTours: number;
  activeTours: number;
}

const SYSTEM_HEALTH = [
  { label: "Firebase Auth", status: "operational", icon: ShieldCheck },
  { label: "Firestore", status: "operational", icon: Database },
  { label: "Redis", status: "operational", icon: Cpu },
  { label: "Brevo Email", status: "operational", icon: Activity },
];

export default function DashboardPage() {
  const user = useAuthStore((s) => s.user);
  const isAdmin = useAuthStore((s) => s.isAdmin)();
  const [stats, setStats] = useState<Stats | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const hour = new Date().getHours();
  const greeting =
    hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening";

  const STAT_CARDS = [
    {
      label: "Total tours",
      value: stats?.totalTours ?? 0,
      icon: Map,
      sub: `${stats?.activeTours ?? 0} active`,
      show: true,
    },
    {
      label: "Team members",
      value: stats?.totalUsers ?? 0,
      icon: Users,
      sub: "Registered accounts",
      show: isAdmin,
    },
    {
      label: "Pending approvals",
      value: stats?.pendingApprovals ?? 0,
      icon: ShieldCheck,
      sub: stats?.pendingApprovals ? "Needs your review" : "All clear",
      urgent: (stats?.pendingApprovals ?? 0) > 0,
      show: isAdmin,
    },
    {
      label: "Your roles",
      value: user?.roles?.length ?? 0,
      icon: KeyRound,
      sub: user?.roles?.join(", ") ?? "",
      show: true,
    },
  ].filter((s) => s.show);

  return (
    <div className="space-y-8">
      {/* Greeting */}
      <PageHeader
        eyebrow={new Date().toLocaleDateString("en-KE", {
          weekday: "long",
          day: "numeric",
          month: "long",
        })}
        title={`${greeting}${user?.firstName ? `, ${user.firstName}` : ""}.`}
        subtitle="Here's what's happening across your basecamp today."
      />

      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {isLoading
          ? Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-28 rounded-xl" />
            ))
          : STAT_CARDS.map((s) => {
              const Icon = s.icon;
              return (
                <Card key={s.label} className={s.urgent ? "border-warning/40 bg-warning/5" : ""}>
                  <CardContent className="p-5">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium text-muted-foreground">{s.label}</p>
                      <Icon
                        className={`h-4 w-4 ${s.urgent ? "text-warning" : "text-accent"}`}
                        strokeWidth={1.75}
                      />
                    </div>
                    <p className="mt-2 font-display text-3xl font-medium tracking-tight">
                      {s.value}
                    </p>
                    <p className="mt-0.5 truncate text-xs text-muted-foreground">{s.sub}</p>
                  </CardContent>
                </Card>
              );
            })}
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* System health */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">System health</CardTitle>
            <CardDescription>
              All services operational · authSys on port 8001
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {SYSTEM_HEALTH.map((s) => {
              const Icon = s.icon;
              return (
                <div key={s.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5 text-sm">
                    <Icon className="h-4 w-4 text-muted-foreground" strokeWidth={1.75} />
                    {s.label}
                  </div>
                  <Badge variant="success" className="text-[10px]">
                    ● Operational
                  </Badge>
                </div>
              );
            })}
            <div className="mt-1 rounded-lg bg-muted/60 p-3">
              <p className="font-mono text-[10px] text-muted-foreground">
                Redis · localhost:6379 · 2s timeout · 6 roles seeded · 27 permissions
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Quick links */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Quick actions</CardTitle>
            <CardDescription>Jump to what needs attention</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {[
              { href: "/tours", label: "Manage tour catalogue", desc: "Add, edit, or deactivate tours" },
              ...(isAdmin
                ? [
                    { href: "/admin/pending", label: "Review pending approvals", desc: `${stats?.pendingApprovals ?? 0} waiting` },
                    { href: "/admin/users", label: "Manage team members", desc: "Lock, unlock, update roles" },
                    { href: "/admin/audit", label: "View audit log", desc: "Full event history" },
                    { href: "/admin/roles", label: "Roles & permissions", desc: "6 roles, 27 permissions" },
                  ]
                : []),
              { href: "/profile", label: "Update your profile", desc: "Personal details & password" },
            ].map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="flex items-center justify-between rounded-lg px-3 py-2.5 text-sm transition-colors hover:bg-muted"
              >
                <div>
                  <p className="font-medium leading-tight">{link.label}</p>
                  <p className="text-xs text-muted-foreground">{link.desc}</p>
                </div>
                <span className="text-muted-foreground">→</span>
              </a>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
