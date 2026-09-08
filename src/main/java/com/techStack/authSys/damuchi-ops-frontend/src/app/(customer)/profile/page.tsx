"use client";

import {
    Mail,
    Shield,
    BadgeCheck,
    Sparkles,
    UserRound,
} from "lucide-react";

import { useAuthStore } from "@/store/auth-store";

import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    Avatar,
    AvatarFallback,
    AvatarImage,
} from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";

const STATUS_BADGE: Record<
    string,
    "success" | "warning" | "destructive"
> = {
    ACTIVE: "success",
    PENDING_APPROVAL: "warning",
    DISABLED: "destructive",
};

const STATUS_LABEL: Record<string, string> = {
    ACTIVE: "Active member",
    PENDING_APPROVAL: "Pending approval",
    DISABLED: "Account disabled",
};

export default function ProfilePage() {
    const user = useAuthStore((s) => s.user);

    /*
     * Loading / hydration state
     */
    if (!user) {
        return (
            <div className="mx-auto w-full max-w-4xl space-y-6">
                <Skeleton className="h-48 w-full rounded-2xl" />

                <div className="flex flex-col items-center gap-3">
                    <Skeleton className="-mt-14 h-24 w-24 rounded-full" />
                    <Skeleton className="h-6 w-40" />
                    <Skeleton className="h-4 w-56" />
                    <Skeleton className="h-6 w-28 rounded-full" />
                </div>

                <Card className="border-border/60">
                    <CardContent className="space-y-4 p-6">
                        {Array.from({ length: 3 }).map((_, i) => (
                            <Skeleton key={i} className="h-14 w-full rounded-xl" />
                        ))}
                    </CardContent>
                </Card>
            </div>
        );
    }

    const initials = user.displayName
        ? user.displayName
            .split(" ")
            .map((part) => part[0])
            .slice(0, 2)
            .join("")
            .toUpperCase()
        : "?";

    const statusVariant =
        STATUS_BADGE[user.status] ?? "outline";

    const statusLabel =
        STATUS_LABEL[user.status] ??
        user.status.replace(/_/g, " ");

    return (
        <div className="mx-auto w-full max-w-4xl">
            {/* Page heading */}
            <div className="mb-6">
                <p className="font-mono text-xs uppercase tracking-[0.15em] text-savanna">
                    Account
                </p>

                <div className="mt-1 flex items-center gap-3">
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-savanna/10 text-savanna">
                        <UserRound className="h-4 w-4" />
                    </div>

                    <div>
                        <h1 className="font-display text-2xl font-semibold tracking-tight text-earth sm:text-3xl">
                            My profile
                        </h1>

                        <p className="mt-1 text-sm text-stone">
                            Manage your account information and access details.
                        </p>
                    </div>
                </div>
            </div>

            {/* Profile hero */}
            <section className="relative overflow-hidden rounded-2xl border border-border/60 bg-card shadow-sm">
                {/* Background */}
                <div className="absolute inset-0 bg-gradient-to-br from-savanna/20 via-savanna/5 to-earth/5" />

                <div
                    className="absolute inset-0 opacity-25"
                    style={{
                        backgroundImage:
                            "radial-gradient(circle at 20% 20%, white 0.5px, transparent 0.5px)",
                        backgroundSize: "16px 16px",
                    }}
                    aria-hidden="true"
                />

                {/* Decorative glow */}
                <div
                    className="absolute -right-20 -top-20 h-56 w-56 rounded-full bg-savanna/10 blur-3xl"
                    aria-hidden="true"
                />

                <div className="relative px-5 pb-7 pt-8 sm:px-8 sm:pt-10">
                    <div className="flex flex-col items-center text-center">
                        {/* Avatar */}
                        <Avatar className="h-24 w-24 border-4 border-background shadow-xl sm:h-28 sm:w-28">
                            {user.profilePhotoUrl && (
                                <AvatarImage
                                    src={user.profilePhotoUrl}
                                    alt={user.displayName}
                                />
                            )}

                            <AvatarFallback className="bg-savanna/15 font-display text-2xl font-semibold text-savanna sm:text-3xl">
                                {initials}
                            </AvatarFallback>
                        </Avatar>

                        {/* Identity */}
                        <div className="mt-4">
                            <h2 className="font-display text-2xl font-semibold tracking-tight text-earth">
                                {user.displayName}
                            </h2>

                            <p className="mt-1 text-sm text-stone">
                                {user.email}
                            </p>
                        </div>

                        {/* Status */}
                        <Badge
                            variant={statusVariant}
                            className="mt-3 rounded-full px-3 py-1"
                        >
                            {statusLabel}
                        </Badge>

                        {/* Roles */}
                        {user.roles?.length > 0 && (
                            <div className="mt-4 flex flex-wrap justify-center gap-1.5">
                                {user.roles.map((role) => (
                                    <Badge
                                        key={role}
                                        variant="outline"
                                        className="rounded-full border-earth/10 bg-earth/5 px-3 text-[11px] font-medium text-earth"
                                    >
                                        {role}
                                    </Badge>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </section>

            {/* Profile information */}
            <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_0.8fr]">
                {/* Account details */}
                <Card className="overflow-hidden border-border/60 shadow-sm">
                    <CardContent className="p-0">
                        <div className="border-b border-border/60 px-5 py-4 sm:px-6">
                            <h3 className="font-display text-base font-semibold text-earth">
                                Account information
                            </h3>

                            <p className="mt-1 text-xs text-stone">
                                Your current account and access information.
                            </p>
                        </div>

                        <div className="divide-y divide-border/60">
                            {/* Email */}
                            <div className="flex items-center gap-4 px-5 py-4 sm:px-6">
                                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-savanna/10 text-savanna">
                                    <Mail className="h-4 w-4" />
                                </div>

                                <div className="min-w-0">
                                    <p className="text-xs text-stone">
                                        Email address
                                    </p>

                                    <p className="mt-0.5 truncate text-sm font-medium text-earth">
                                        {user.email}
                                    </p>
                                </div>
                            </div>

                            {/* Roles */}
                            <div className="flex items-center gap-4 px-5 py-4 sm:px-6">
                                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-savanna/10 text-savanna">
                                    <Shield className="h-4 w-4" />
                                </div>

                                <div className="min-w-0">
                                    <p className="text-xs text-stone">
                                        Access level
                                    </p>

                                    <p className="mt-0.5 text-sm font-medium text-earth">
                                        {user.roles.join(", ")}
                                    </p>
                                </div>
                            </div>

                            {/* Permissions */}
                            {user.permissions?.length > 0 && (
                                <div className="flex items-center gap-4 px-5 py-4 sm:px-6">
                                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-savanna/10 text-savanna">
                                        <BadgeCheck className="h-4 w-4" />
                                    </div>

                                    <div className="min-w-0">
                                        <p className="text-xs text-stone">
                                            Permissions
                                        </p>

                                        <p className="mt-0.5 text-sm font-medium text-earth">
                                            {user.permissions.length} granted
                                        </p>

                                        <p className="mt-0.5 text-xs text-stone">
                                            Resolved from your assigned role.
                                        </p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </CardContent>
                </Card>

                {/* Security / help */}
                <div className="space-y-6">
                    <Card className="border-border/60 shadow-sm">
                        <CardContent className="p-5 sm:p-6">
                            <div className="flex items-start gap-3">
                                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-savanna/10 text-savanna">
                                    <Sparkles className="h-4 w-4" />
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-earth">
                                        Account security
                                    </h3>

                                    <p className="mt-1 text-xs leading-relaxed text-stone">
                                        Your account access is controlled centrally to
                                        help keep your safari bookings and personal
                                        information secure.
                                    </p>
                                </div>
                            </div>
                        </CardContent>
                    </Card>

                    <div className="rounded-2xl border border-savanna/20 bg-savanna/5 px-5 py-4 sm:px-6">
                        <div className="flex items-start gap-3">
                            <Shield className="mt-0.5 h-4 w-4 shrink-0 text-savanna" />

                            <p className="text-xs leading-relaxed text-stone">
                                Need to update your name, email, or password?
                                Reach out to your administrator. Account details
                                are managed centrally.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}