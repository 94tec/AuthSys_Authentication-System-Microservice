"use client";

import { useCallback, useEffect, useState } from "react";
import {
    Bell,
    RefreshCw,
    Inbox,
    UserRoundPlus,
    ArrowUpRight,
    Clock3,
} from "lucide-react";
import { useRouter } from "next/navigation";

import { enquiryApi } from "@/lib/enquiry-api";
import type { EnquiryDashboardSummary } from "@/types/enquiry-types";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";

export function NotificationBell() {
    const router = useRouter();

    const [summary, setSummary] =
        useState<EnquiryDashboardSummary | null>(null);

    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [open, setOpen] = useState(false);

    const loadSummary = useCallback(
        async (showRefresh = false) => {
            try {
                if (showRefresh) {
                    setRefreshing(true);
                } else {
                    setLoading(true);
                }

                const result =
                    await enquiryApi.adminDashboardSummary();

                setSummary(result);
            } catch {
                // Notification center should never break the admin header.
            } finally {
                setLoading(false);
                setRefreshing(false);
            }
        },
        []
    );

    /*
     * Initial load + background refresh.
     */
    useEffect(() => {
        loadSummary();

        const interval = setInterval(() => {
            loadSummary();
        }, 60_000);

        return () => clearInterval(interval);
    }, [loadSummary]);

    /*
     * Refresh immediately whenever the modal opens.
     */
    useEffect(() => {
        if (open) {
            loadSummary(true);
        }
    }, [open, loadSummary]);

    const unassignedCount =
        summary?.unassignedCount ?? 0;

    const newCount =
        summary?.newCount ?? 0;

    const totalNeedsAttention =
        unassignedCount;

    function openEnquiries() {
        setOpen(false);
        router.push("/enquiries");
    }

    function openUnassigned() {
        setOpen(false);
        router.push("/enquiries?filter=unassigned");
    }

    function openNew() {
        setOpen(false);
        router.push("/enquiries?filter=new");
    }

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                <button
                    type="button"
                    className={[
                        "relative flex h-9 w-9 items-center justify-center",
                        "rounded-lg text-muted-foreground",
                        "transition-all duration-200",
                        "hover:bg-muted hover:text-foreground",
                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                        "active:scale-95",
                    ].join(" ")}
                    aria-label={
                        totalNeedsAttention > 0
                            ? `Notifications, ${totalNeedsAttention} need action`
                            : "Notifications"
                    }
                >
                    <Bell className="h-[17px] w-[17px]" />

                    {totalNeedsAttention > 0 && (
                        <span
                            className={[
                                "absolute -right-1 -top-1",
                                "flex h-[18px] min-w-[18px] items-center justify-center",
                                "rounded-full border-2 border-background",
                                "bg-destructive px-1",
                                "text-[9px] font-bold leading-none text-destructive-foreground",
                                "shadow-sm",
                            ].join(" ")}
                        >
                    {totalNeedsAttention > 99 ? "99+" : totalNeedsAttention}
                </span>
                    )}
                </button>
            </DialogTrigger>

            <DialogContent
                className={[
                    "w-[calc(100%-1rem)] sm:w-[calc(100%-2rem)]",
                    "max-w-lg",
                    "gap-0 overflow-hidden p-0",
                    "rounded-2xl",
                    "border-border/80",
                    "bg-background",
                    "shadow-2xl shadow-black/10",
                ].join(" ")}
            >
                {/* ─────────────────────────────────────────────
            HEADER
        ───────────────────────────────────────────── */}
                <DialogHeader className="relative border-b border-border/70">
                    <div className="px-5 py-4 sm:px-6 sm:py-5">
                        <div className="flex items-center justify-between gap-4 pr-8">
                            <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                    <DialogTitle className="font-display text-lg font-semibold tracking-tight">
                                        Notifications
                                    </DialogTitle>

                                    {totalNeedsAttention > 0 && (
                                        <Badge
                                            variant="destructive"
                                            className="h-5 rounded-full px-2 text-[10px] font-semibold"
                                        >
                                            {totalNeedsAttention} need action
                                        </Badge>
                                    )}
                                </div>

                                <DialogDescription className="mt-1.5 max-w-sm text-xs leading-relaxed text-muted-foreground">
                                    Stay on top of customer enquiries and follow-ups
                                    that need your attention.
                                </DialogDescription>
                            </div>

                            <Button
                                type="button"
                                variant="outline"
                                size="icon"
                                className={[
                                    "h-8 w-8 shrink-0 rounded-lg",
                                    "border-border/70 bg-background",
                                    "text-muted-foreground",
                                    "hover:bg-muted hover:text-foreground",
                                ].join(" ")}
                                onClick={() => loadSummary(true)}
                                disabled={refreshing}
                                aria-label="Refresh notifications"
                            >
                                <RefreshCw
                                    className={[
                                        "h-3.5 w-3.5",
                                        refreshing ? "animate-spin" : "",
                                    ].join(" ")}
                                />
                            </Button>
                        </div>

                        {/* Quick summary */}
                        {!loading && summary && (
                            <div className="mt-4 grid grid-cols-2 gap-2">
                                <div className="rounded-xl border border-border/70 bg-muted/30 px-3 py-2.5">
                                    <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                                        Needs action
                                    </p>
                                    <p className="mt-0.5 text-lg font-semibold tracking-tight">
                                        {totalNeedsAttention}
                                    </p>
                                </div>

                                <div className="rounded-xl border border-border/70 bg-muted/30 px-3 py-2.5">
                                    <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                                        New
                                    </p>
                                    <p className="mt-0.5 text-lg font-semibold tracking-tight">
                                        {newCount}
                                    </p>
                                </div>
                            </div>
                        )}
                    </div>
                </DialogHeader>

                {/* ─────────────────────────────────────────────
            BODY
        ───────────────────────────────────────────── */}
                <div className="max-h-[min(520px,65vh)] overflow-y-auto">
                    <div className="space-y-3 p-4 sm:p-5">
                        {loading && !summary ? (
                            <div className="space-y-3">
                                <NotificationSkeleton />
                                <NotificationSkeleton />
                            </div>
                        ) : (
                            <>
                                {/* UNASSIGNED */}
                                <button
                                    type="button"
                                    onClick={openUnassigned}
                                    disabled={unassignedCount === 0}
                                    className={[
                                        "group relative flex w-full items-center gap-3.5",
                                        "rounded-xl border p-4 text-left",
                                        "transition-all duration-200",
                                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                                        unassignedCount > 0
                                            ? [
                                                "border-amber-500/20",
                                                "bg-amber-500/[0.045]",
                                                "hover:-translate-y-[1px]",
                                                "hover:border-amber-500/35",
                                                "hover:bg-amber-500/[0.08]",
                                                "hover:shadow-sm",
                                            ].join(" ")
                                            : [
                                                "border-border/70",
                                                "bg-muted/20",
                                                "opacity-60",
                                            ].join(" "),
                                    ].join(" ")}
                                >
                                    <div
                                        className={[
                                            "flex h-11 w-11 shrink-0 items-center justify-center",
                                            "rounded-xl",
                                            "transition-transform duration-200",
                                            unassignedCount > 0
                                                ? "bg-amber-500/10 text-amber-600 group-hover:scale-105"
                                                : "bg-muted text-muted-foreground",
                                        ].join(" ")}
                                    >
                                        <UserRoundPlus className="h-[18px] w-[18px]" />
                                    </div>

                                    <div className="min-w-0 flex-1">
                                        <div className="flex items-center gap-2">
                                            <p className="truncate text-sm font-semibold text-foreground">
                                                Unassigned enquiries
                                            </p>

                                            {unassignedCount > 0 && (
                                                <span className="shrink-0 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-bold text-amber-600">
                                            {unassignedCount}
                                        </span>
                                            )}
                                        </div>

                                        <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
                                            Customer enquiries waiting for an admin
                                            or staff member to take ownership.
                                        </p>

                                        {unassignedCount > 0 && (
                                            <span className="mt-2 inline-flex items-center gap-1 text-[11px] font-medium text-amber-600">
                                        Review now
                                        <ArrowUpRight className="h-3 w-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                                    </span>
                                        )}
                                    </div>

                                    {unassignedCount > 0 && (
                                        <div className="hidden shrink-0 sm:block">
                                            <ArrowUpRight className="h-4 w-4 text-muted-foreground/50 transition-all group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-foreground" />
                                        </div>
                                    )}
                                </button>

                                {/* NEW ENQUIRIES */}
                                <button
                                    type="button"
                                    onClick={openNew}
                                    disabled={newCount === 0}
                                    className={[
                                        "group relative flex w-full items-center gap-3.5",
                                        "rounded-xl border p-4 text-left",
                                        "transition-all duration-200",
                                        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                                        newCount > 0
                                            ? [
                                                "border-primary/20",
                                                "bg-primary/[0.035]",
                                                "hover:-translate-y-[1px]",
                                                "hover:border-primary/35",
                                                "hover:bg-primary/[0.07]",
                                                "hover:shadow-sm",
                                            ].join(" ")
                                            : [
                                                "border-border/70",
                                                "bg-muted/20",
                                                "opacity-60",
                                            ].join(" "),
                                    ].join(" ")}
                                >
                                    <div
                                        className={[
                                            "flex h-11 w-11 shrink-0 items-center justify-center",
                                            "rounded-xl",
                                            "transition-transform duration-200",
                                            newCount > 0
                                                ? "bg-primary/10 text-primary group-hover:scale-105"
                                                : "bg-muted text-muted-foreground",
                                        ].join(" ")}
                                    >
                                        <Inbox className="h-[18px] w-[18px]" />
                                    </div>

                                    <div className="min-w-0 flex-1">
                                        <div className="flex items-center gap-2">
                                            <p className="truncate text-sm font-semibold text-foreground">
                                                New enquiries
                                            </p>

                                            {newCount > 0 && (
                                                <span className="shrink-0 rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-bold text-primary">
                                            {newCount}
                                        </span>
                                            )}
                                        </div>

                                        <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
                                            Recently submitted enquiries from
                                            customers browsing your safaris.
                                        </p>

                                        {newCount > 0 && (
                                            <span className="mt-2 inline-flex items-center gap-1 text-[11px] font-medium text-primary">
                                        View new enquiries
                                        <ArrowUpRight className="h-3 w-3 transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5" />
                                    </span>
                                        )}
                                    </div>

                                    {newCount > 0 && (
                                        <div className="hidden shrink-0 sm:block">
                                            <ArrowUpRight className="h-4 w-4 text-muted-foreground/50 transition-all group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-foreground" />
                                        </div>
                                    )}
                                </button>

                                {/* EMPTY STATE */}
                                {totalNeedsAttention === 0 && newCount === 0 && (
                                    <div className="rounded-xl border border-dashed border-border bg-muted/[0.18] px-5 py-10 text-center">
                                        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-500/10 text-emerald-600">
                                            <Bell className="h-5 w-5" />
                                        </div>

                                        <p className="mt-4 text-sm font-semibold">
                                            You're all caught up
                                        </p>

                                        <p className="mx-auto mt-1.5 max-w-xs text-xs leading-relaxed text-muted-foreground">
                                            There are no new enquiries or pending
                                            actions requiring your attention.
                                        </p>
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                </div>

                {/* ─────────────────────────────────────────────
            FOOTER
        ───────────────────────────────────────────── */}
                <div className="border-t border-border/70 bg-muted/[0.18] px-4 py-3.5 sm:px-5">
                    <Button
                        type="button"
                        className="h-10 w-full rounded-xl"
                        onClick={openEnquiries}
                    >
                        <Inbox className="mr-2 h-4 w-4" />
                        Open enquiry queue
                        <ArrowUpRight className="ml-auto h-4 w-4" />
                    </Button>

                    <div className="mt-2.5 flex items-center justify-center gap-1.5 text-[10px] text-muted-foreground">
                        <Clock3 className="h-3 w-3" />
                        Automatically updated every minute
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    );
}

function NotificationSkeleton() {
    return (
        <div className="flex items-center gap-3 rounded-xl border border-border p-3.5">
            <div className="h-10 w-10 animate-pulse rounded-xl bg-muted" />

            <div className="flex-1 space-y-2">
                <div className="h-3 w-32 animate-pulse rounded bg-muted" />
                <div className="h-2.5 w-48 max-w-full animate-pulse rounded bg-muted" />
            </div>
        </div>
    );
}