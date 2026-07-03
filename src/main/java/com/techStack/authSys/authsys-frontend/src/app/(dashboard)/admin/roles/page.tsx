"use client";

import { useEffect, useState } from "react";
import { Key, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { adminApi } from "@/lib/admin-api";
import type { ApiError, RolePermissions } from "@/types/auth";

// Permission count targets from your startup log
const ROLE_META: Record<string, { color: string; description: string }> = {
  SUPER_ADMIN:  { color: "bg-accent/10 text-accent border-accent/20", description: "Full system access — 27 permissions" },
  ADMIN:        { color: "bg-accent/10 text-accent border-accent/20", description: "Full admin access — 27 permissions" },
  MANAGER:      { color: "bg-secondary/10 text-secondary border-secondary/20", description: "Operations management — 14 permissions" },
  DESIGNER:     { color: "bg-blue-500/10 text-blue-600 border-blue-200", description: "Content & design access — 11 permissions" },
  USER:         { color: "bg-muted text-muted-foreground border-border", description: "Standard access — 7 permissions" },
  GUEST:        { color: "bg-muted/50 text-muted-foreground border-border", description: "Read-only access — 1 permission" },
};

export default function RolesPage() {
  const [roles, setRoles] = useState<RolePermissions[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    adminApi.getAllRolePermissions()
      .then(setRoles)
      .catch((err: ApiError) =>
        toast.error(err.message || "Couldn't load role permissions.")
      )
      .finally(() => setIsLoading(false));
  }, []);

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Admin"
        title="Roles & permissions"
        subtitle="Permission matrix seeded from your YAML config at startup. 6 roles, 27 total permissions."
      />

      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-48 rounded-xl" />
          ))}
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {(roles.length > 0 ? roles : Object.keys(ROLE_META).map((role) => ({
            role: role as any,
            permissions: [],
            permissionCount: 0,
          }))).map((r) => {
            const meta = ROLE_META[r.role] ?? ROLE_META["USER"];
            return (
              <Card key={r.role} className="border-border">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${meta.color}`}>
                      <ShieldCheck className="h-3 w-3" />
                      {r.role.replace(/_/g, " ")}
                    </div>
                    <span className="font-display text-xl font-medium">
                      {r.permissionCount || ROLE_META[r.role]?.description.match(/\d+/)?.[0] ?? "?"}
                    </span>
                  </div>
                  <CardTitle className="text-sm font-normal text-muted-foreground">
                    {meta.description}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {r.permissions.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {r.permissions.slice(0, 8).map((p) => (
                        <Badge key={p} variant="outline" className="text-[10px]">
                          {p}
                        </Badge>
                      ))}
                      {r.permissions.length > 8 && (
                        <Badge variant="outline" className="text-[10px] text-muted-foreground">
                          +{r.permissions.length - 8} more
                        </Badge>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      Permissions loaded from Firestore at runtime via PermissionYamlLoader.
                    </p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Key className="h-4 w-4 text-accent" />
          How permissions work in authSys
        </div>
        <p className="mt-2 text-sm text-muted-foreground leading-relaxed">
          Permissions are seeded from <code className="rounded bg-muted px-1 font-mono text-xs">permissions.yml</code> at startup
          via <code className="rounded bg-muted px-1 font-mono text-xs">PermissionSeeder</code>, stored in Firestore, and cached
          in Redis with a 30-second eviction cycle (confirmed in your logs as{" "}
          <code className="rounded bg-muted px-1 font-mono text-xs">rd-expiry-bot</code> threads).
          The <code className="rounded bg-muted px-1 font-mono text-xs">PermissionService</code> resolves effective permissions
          per user at auth time via <code className="rounded bg-muted px-1 font-mono text-xs">FirestoreUserPermissionsRepository</code>.
        </p>
      </div>
    </div>
  );
}
