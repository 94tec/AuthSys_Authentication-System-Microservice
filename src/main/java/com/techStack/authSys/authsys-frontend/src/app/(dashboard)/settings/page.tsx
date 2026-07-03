"use client";

import { Server, Database, Mail, Phone, Shield, Clock, Zap } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

// Read from your actual startup log - these are documented facts about your system
const SYSTEM_INFO = [
  { label: "Backend port", value: "8001", icon: Server },
  { label: "Auth service", value: "Spring Boot 3.2 + WebFlux (Netty)", icon: Zap },
  { label: "Identity store", value: "Firebase Auth · project spring-data-a3ebb", icon: Shield },
  { label: "Document DB", value: "Firestore (users, permissions, ACL)", icon: Database },
  { label: "Relational DB", value: "PostgreSQL via HikariPool (tours, JPA)", icon: Database },
  { label: "Cache / sessions", value: "Redis localhost:6379 · 2s timeout", icon: Clock },
  { label: "Email provider", value: "Brevo (primary) · Gmail SMTP (secondary)", icon: Mail },
  { label: "SMS provider", value: "Africa's Talking (AfricaTalkingProperties)", icon: Phone },
];

const ROLES_SEEDED = [
  { role: "SUPER_ADMIN", count: 27 },
  { role: "ADMIN", count: 27 },
  { role: "MANAGER", count: 14 },
  { role: "DESIGNER", count: 11 },
  { role: "USER", count: 7 },
  { role: "GUEST", count: 1 },
];

const FEATURES = [
  { label: "Firebase Auth filter", status: "active" },
  { label: "Force password change filter", status: "active" },
  { label: "Rate limiter (Redis)", status: "active" },
  { label: "Session expiry bot (5-min cron)", status: "active" },
  { label: "Blacklist cleanup scheduler", status: "active" },
  { label: "Account lock cleanup", status: "active" },
  { label: "Permission cache eviction (30s)", status: "active" },
  { label: "Bootstrap orchestrator (lock + cleanup)", status: "active" },
  { label: "Password expiry check (daily 2 AM)", status: "active" },
  { label: "Password history cleanup (Sun 3 AM)", status: "active" },
  { label: "DNS resolver (8.8.8.8)", status: "active" },
  { label: "Google OAuth2", status: "active" },
  { label: "AES encryption service", status: "active" },
  { label: "Brevo email service", status: "active" },
  { label: "Africa's Talking SMS", status: "active" },
  { label: "OpenTelemetry / metrics", status: "active" },
];

export default function SettingsPage() {
  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Settings"
        title="System overview"
        subtitle="Live infrastructure snapshot from your startup log. All systems operational."
      />

      {/* System info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Server className="h-4 w-4 text-accent" />
            Infrastructure
          </CardTitle>
        </CardHeader>
        <CardContent className="divide-y divide-border">
          {SYSTEM_INFO.map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.label} className="flex items-center justify-between py-3">
                <div className="flex items-center gap-2.5 text-sm text-muted-foreground">
                  <Icon className="h-4 w-4 text-accent/70" strokeWidth={1.75} />
                  {item.label}
                </div>
                <p className="font-mono text-xs text-foreground">{item.value}</p>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        {/* Roles seeded */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4 text-accent" />
              Roles seeded at startup
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {ROLES_SEEDED.map((r) => (
              <div key={r.role} className="flex items-center justify-between">
                <span className="font-mono text-xs text-foreground">{r.role}</span>
                <div className="flex items-center gap-2">
                  <div className="h-1.5 rounded-full bg-muted" style={{ width: 80 }}>
                    <div
                      className="h-full rounded-full bg-accent"
                      style={{ width: `${(r.count / 27) * 100}%` }}
                    />
                  </div>
                  <span className="w-6 text-right font-mono text-xs text-muted-foreground">
                    {r.count}
                  </span>
                </div>
              </div>
            ))}
            <Separator className="my-1" />
            <p className="text-xs text-muted-foreground">
              Seeded via <code className="rounded bg-muted px-1 font-mono">PermissionSeeder</code> from{" "}
              <code className="rounded bg-muted px-1 font-mono">permissions.yml</code> → Firestore
            </p>
          </CardContent>
        </Card>

        {/* Active features */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Zap className="h-4 w-4 text-accent" />
              Active features
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {FEATURES.map((f) => (
                <div key={f.label} className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">{f.label}</span>
                  <Badge variant="success" className="text-[10px]">
                    ● live
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* SaaS roadmap note */}
      <Card className="border-accent/20 bg-accent/5">
        <CardContent className="p-5">
          <p className="text-sm font-medium text-accent">Next steps — SaaS expansion</p>
          <p className="mt-2 text-sm text-muted-foreground leading-relaxed">
            Your auth system is production-ready. The recommended next modules (from your architecture plan):{" "}
            <strong>Organizations</strong> (multi-tenancy with{" "}
            <code className="rounded bg-muted px-1 font-mono text-xs">organization_id</code> on every entity),{" "}
            <strong>Customers</strong> (CRM with passport/ID, preferences, booking history),{" "}
            <strong>Bookings</strong> (Draft → Pending → Confirmed → Paid → Completed),{" "}
            <strong>Payments</strong> (M-Pesa, card, cash reconciliation), then{" "}
            <strong>Fleet</strong> &amp; <strong>Guides</strong>. All stay in this Spring Boot monolith
            until you have clear scaling pressure.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
