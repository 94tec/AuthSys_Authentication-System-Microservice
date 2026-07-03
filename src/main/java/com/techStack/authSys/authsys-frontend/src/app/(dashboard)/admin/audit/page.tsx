"use client";

import { useCallback, useEffect, useState } from "react";
import { FileText, RefreshCw, Search } from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";
import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { adminApi } from "@/lib/admin-api";
import type { ApiError, AuditLog } from "@/types/auth";

const SEVERITY_BADGE: Record<string, "success" | "warning" | "destructive"> = {
  INFO: "success",
  WARN: "warning",
  ERROR: "destructive",
};

export default function AuditLogPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await adminApi.getAuditLogs(0, 50);
      setLogs(data.content);
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't load audit logs.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = logs.filter(
    (l) =>
      search === "" ||
      `${l.action} ${l.userEmail} ${l.actionType}`.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Admin"
        title="Audit log"
        subtitle="Every action tracked — who, what, when, from where. Powered by AuditLogService."
        action={
          <Button variant="outline" size="sm" onClick={load} disabled={isLoading}>
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search by action, user…"
          className="pl-9"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full rounded-lg" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No audit entries yet"
          description="Auth events, role changes, and login activity will appear here."
        />
      ) : (
        <div className="rounded-xl border border-border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Action</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((log) => (
                <TableRow key={log.id}>
                  <TableCell>
                    <div>
                      <p className="font-medium font-mono text-xs">{log.action}</p>
                      {log.entityType && (
                        <p className="text-[10px] text-muted-foreground">
                          {log.entityType}{log.entityId ? ` · ${log.entityId.slice(0, 8)}…` : ""}
                        </p>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {log.userEmail ?? log.userId?.slice(0, 12) + "…"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={SEVERITY_BADGE[log.severity] ?? "outline"} className="text-[10px]">
                      {log.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {log.ipAddress ?? "—"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {format(new Date(log.timestamp), "dd MMM · HH:mm:ss")}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
