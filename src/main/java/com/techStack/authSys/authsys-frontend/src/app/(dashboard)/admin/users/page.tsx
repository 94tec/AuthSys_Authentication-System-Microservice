"use client";

import { useCallback, useEffect, useState } from "react";
import { Users, Lock, Unlock, RefreshCw, Search } from "lucide-react";
import { toast } from "sonner";
import { formatDistanceToNow } from "date-fns";
import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { adminApi } from "@/lib/admin-api";
import type { ApiError, User } from "@/types/auth";

const STATUS_BADGE: Record<string, "success" | "warning" | "destructive" | "outline"> = {
  ACTIVE: "success",
  PENDING_APPROVAL: "warning",
  REJECTED: "destructive",
  LOCKED: "destructive",
  DISABLED: "outline",
};

export default function TeamPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await adminApi.getAllUsers(0, 50);
      setUsers(data.content);
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't load team members.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleLockToggle(user: User) {
    setProcessingId(user.id);
    try {
      if (user.status === "LOCKED") {
        await adminApi.unlockUser(user.id);
        setUsers((prev) => prev.map((u) => u.id === user.id ? { ...u, status: "ACTIVE" } : u));
        toast.success(`${user.firstName} unlocked`);
      } else {
        await adminApi.lockUser(user.id);
        setUsers((prev) => prev.map((u) => u.id === user.id ? { ...u, status: "LOCKED" } : u));
        toast.success(`${user.firstName} locked`);
      }
    } catch (err) {
      toast.error((err as ApiError).message || "Action failed.");
    } finally {
      setProcessingId(null);
    }
  }

  const filtered = users.filter(
    (u) =>
      search === "" ||
      `${u.firstName} ${u.lastName} ${u.email}`.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Admin"
        title="Team members"
        subtitle={`${users.length} total accounts`}
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
          placeholder="Search by name or email…"
          className="pl-9"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full rounded-lg" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState icon={Users} title="No team members found" description="Try adjusting your search." />
      ) : (
        <div className="rounded-xl border border-border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Member</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Joined</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((user) => {
                const initials = `${user.firstName?.[0] ?? ""}${user.lastName?.[0] ?? ""}`.toUpperCase();
                return (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <Avatar className="h-8 w-8">
                          <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                        </Avatar>
                        <div>
                          <p className="font-medium leading-tight">
                            {user.firstName} {user.lastName}
                          </p>
                          <p className="text-xs text-muted-foreground">{user.email}</p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {user.roles.map((r) => (
                          <Badge key={r} variant="secondary" className="text-[10px]">
                            {r}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={STATUS_BADGE[user.status] ?? "outline"}>
                        {user.status.replace(/_/g, " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {formatDistanceToNow(new Date(user.createdAt), { addSuffix: true })}
                    </TableCell>
                    <TableCell className="text-right">
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={processingId === user.id}
                          >
                            {user.status === "LOCKED" ? (
                              <><Unlock className="h-3.5 w-3.5" /> Unlock</>
                            ) : (
                              <><Lock className="h-3.5 w-3.5" /> Lock</>
                            )}
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>
                              {user.status === "LOCKED" ? "Unlock" : "Lock"} this account?
                            </AlertDialogTitle>
                            <AlertDialogDescription>
                              {user.status === "LOCKED"
                                ? `${user.firstName} will regain access immediately.`
                                : `${user.firstName} will be signed out and unable to log in until unlocked.`}
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => handleLockToggle(user)}>
                              {user.status === "LOCKED" ? "Unlock" : "Lock"} account
                            </AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
