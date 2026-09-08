// app/(admin)/revenue/page.tsx
"use client";

import { useEffect, useState } from "react";
import {
    TrendingUp,
    TrendingDown,
    DollarSign,
    Compass,
    Inbox,
    RefreshCw,
    ArrowUpRight,
    CalendarDays,
} from "lucide-react";
import { toast } from "sonner";

import {
    tourAdminApi,
    type RevenueDashboardResponse,
} from "@/lib/tour-admin-api";
import { enquiryApi } from "@/lib/enquiry-api";
import type { EnquiryDashboardSummary } from "@/types/enquiry-types";

import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

import { PageHeader } from "@/components/layout/page-header";
import { formatCurrency } from "@/lib/utils";
import {router} from "next/client";

type Period = "today" | "thisWeek" | "thisMonth";

const PERIODS: {
    value: Period;
    label: string;
}[] = [
    {
        value: "today",
        label: "Today",
    },
    {
        value: "thisWeek",
        label: "This week",
    },
    {
        value: "thisMonth",
        label: "This month",
    },
];

function MetricCard({
                        label,
                        value,
                        sub,
                        icon: Icon,
                        trend,
                        accent = false,
                    }: {
    label: string;
    value: string;
    sub?: string;
    icon: React.ElementType;
    trend?: number;
    accent?: boolean;
}) {
    const hasTrend = trend !== undefined;
    const positive = trend !== undefined && trend >= 0;

    return (
        <Card className="group relative overflow-hidden border-border/70 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md">
            {accent && (
                <div className="absolute inset-x-0 top-0 h-0.5 bg-primary" />
            )}

            <CardContent className="p-5">
                <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                            {label}
                        </p>

                        <p className="mt-2 truncate font-display text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
                            {value}
                        </p>

                        {sub && (
                            <p className="mt-1.5 truncate text-xs text-muted-foreground">
                                {sub}
                            </p>
                        )}

                        {hasTrend && (
                            <div
                                className={[
                                    "mt-2 inline-flex items-center gap-1",
                                    "rounded-full px-2 py-0.5",
                                    "text-[11px] font-semibold",
                                    positive
                                        ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                                        : "bg-red-500/10 text-red-600 dark:text-red-400",
                                ].join(" ")}
                            >
                                {positive ? (
                                    <TrendingUp className="h-3 w-3" />
                                ) : (
                                    <TrendingDown className="h-3 w-3" />
                                )}

                                <span>
                  {Math.abs(trend).toFixed(1)}%
                </span>

                                <span className="font-normal opacity-80">
                  vs last month
                </span>
                            </div>
                        )}
                    </div>

                    <div
                        className={[
                            "flex h-10 w-10 shrink-0 items-center justify-center",
                            "rounded-xl border",
                            "transition-transform duration-200",
                            "group-hover:scale-105",
                            accent
                                ? "border-primary/10 bg-primary/10 text-primary"
                                : "border-border/70 bg-muted/60 text-muted-foreground",
                        ].join(" ")}
                    >
                        <Icon className="h-4.5 w-4.5" />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}

function MetricCardSkeleton() {
    return (
        <Card className="border-border/70">
            <CardContent className="p-5">
                <div className="flex items-start justify-between gap-4">
                    <div className="space-y-3">
                        <Skeleton className="h-3 w-24" />
                        <Skeleton className="h-8 w-32" />
                        <Skeleton className="h-3 w-28" />
                    </div>

                    <Skeleton className="h-10 w-10 rounded-xl" />
                </div>
            </CardContent>
        </Card>
    );
}

function DashboardSkeleton() {
    return (
        <div className="space-y-6">
            <div className="space-y-3">
                <Skeleton className="h-3 w-24" />
                <Skeleton className="h-9 w-56" />
                <Skeleton className="h-4 w-80 max-w-full" />
            </div>

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                {Array.from({ length: 4 }).map((_, index) => (
                    <MetricCardSkeleton key={index} />
                ))}
            </div>

            <Skeleton className="h-32 rounded-xl" />
        </div>
    );
}

function ErrorState({
                        message,
                        onRetry,
                    }: {
    message: string;
    onRetry: () => void;
}) {
    return (
        <Card className="border-destructive/20">
            <CardContent className="flex flex-col items-center justify-center px-6 py-12 text-center">
                <div className="flex h-11 w-11 items-center justify-center rounded-full bg-destructive/10 text-destructive">
                    <RefreshCw className="h-5 w-5" />
                </div>

                <h3 className="mt-4 font-display text-base font-semibold">
                    Couldn't load dashboard
                </h3>

                <p className="mt-1 max-w-md text-sm text-muted-foreground">
                    {message}
                </p>

                <Button
                    variant="outline"
                    size="sm"
                    className="mt-5"
                    onClick={onRetry}
                >
                    <RefreshCw className="mr-2 h-3.5 w-3.5" />
                    Try again
                </Button>
            </CardContent>
        </Card>
    );
}

export default function RevenueDashboardPage() {
    const [revenue, setRevenue] =
        useState<RevenueDashboardResponse | null>(null);

    const [enquiries, setEnquiries] =
        useState<EnquiryDashboardSummary | null>(null);

    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [period, setPeriod] =
        useState<Period>("thisMonth");

    async function loadDashboard(showRefreshState = false) {
        try {
            setError(null);

            if (showRefreshState) {
                setRefreshing(true);
            } else {
                setLoading(true);
            }

            const [revenueData, enquiryData] =
                await Promise.all([
                    tourAdminApi.revenue(),
                    enquiryApi.adminDashboardSummary(),
                ]);

            setRevenue(revenueData);
            setEnquiries(enquiryData);
        } catch (err) {
            const message =
                err instanceof Error
                    ? err.message
                    : "Couldn't load dashboard stats.";

            setError(message);

            toast.error(message);
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    }

    useEffect(() => {
        loadDashboard();
    }, []);

    if (loading) {
        return <DashboardSkeleton />;
    }

    if (error || !revenue) {
        return (
            <div className="space-y-6">
                <PageHeader
                    eyebrow="Revenue"
                    title="Revenue dashboard"
                    subtitle="Track bookings, revenue and customer enquiries."
                />

                <ErrorState
                    message={error ?? "No dashboard data is available."}
                    onRetry={() => loadDashboard()}
                />
            </div>
        );
    }

    const active = revenue[period];

    const enquiryCount = active.enquiryCount ?? 0;
    const newEnquiries = enquiries?.newCount ?? 0;

    return (
        <div className="space-y-6">
            {/* =====================================================
              PAGE HEADER
              ===================================================== */}
            <PageHeader
                eyebrow="Overview"
                title="Revenue dashboard"
                subtitle="Monitor safari sales, revenue and customer demand."
                action={
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => loadDashboard(true)}
                        disabled={refreshing}
                        className="gap-2"
                    >
                        <RefreshCw
                            className={[
                                "h-3.5 w-3.5",
                                refreshing && "animate-spin",
                            ]
                                .filter(Boolean)
                                .join(" ")}
                        />

                        <span className="hidden sm:inline">
              Refresh
            </span>
                    </Button>
                }
            />

            {/* =====================================================
              PERIOD SELECTOR
              ===================================================== */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <CalendarDays className="h-3.5 w-3.5" />
                    <span>Performance period</span>
                </div>

                <div
                    className="inline-flex w-fit items-center rounded-full border border-border bg-muted/40 p-1"
                    role="tablist"
                    aria-label="Revenue period"
                >
                    {PERIODS.map(({ value, label }) => {
                        const activePeriod = period === value;

                        return (
                            <button
                                key={value}
                                type="button"
                                role="tab"
                                aria-selected={activePeriod}
                                onClick={() => setPeriod(value)}
                                className={[
                                    "rounded-full px-3.5 py-1.5",
                                    "text-xs font-medium",
                                    "transition-all duration-200",
                                    "focus-visible:outline-none",
                                    "focus-visible:ring-2",
                                    "focus-visible:ring-primary/40",
                                    activePeriod
                                        ? "bg-background text-foreground shadow-sm"
                                        : "text-muted-foreground hover:text-foreground",
                                ].join(" ")}
                            >
                                {label}
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* =====================================================
          METRICS
          ===================================================== */}
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard
                    label="Actual revenue"
                    value={formatCurrency(
                        active.actualRevenue,
                        "USD"
                    )}
                    sub="Completed bookings"
                    icon={DollarSign}
                    trend={
                        period === "thisMonth"
                            ? revenue.monthOverMonthChangePercent
                            : undefined
                    }
                    accent
                />

                <MetricCard
                    label="Expected revenue"
                    value={formatCurrency(
                        active.expectedRevenue,
                        "USD"
                    )}
                    sub="Open quotes + enquiries"
                    icon={TrendingUp}
                />

                <MetricCard
                    label="Safaris sold"
                    value={String(active.toursSold)}
                    sub="Completed bookings"
                    icon={Compass}
                />

                <MetricCard
                    label="Enquiries"
                    value={String(enquiryCount)}
                    sub={
                        newEnquiries > 0
                            ? `${newEnquiries} new`
                            : "No new enquiries"
                    }
                    icon={Inbox}
                />
            </div>

            {/* =====================================================
          QUICK SUMMARY
          ===================================================== */}
            <Card className="overflow-hidden border-border/70">
                <CardContent className="p-0">
                    <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
                        <div className="min-w-0">
                            <div className="flex items-center gap-2">
                                <p className="text-sm font-semibold">
                                    {period === "today"
                                        ? "Today's performance"
                                        : period === "thisWeek"
                                            ? "This week's performance"
                                            : "This month's performance"}
                                </p>

                                <Badge
                                    variant="secondary"
                                    className="rounded-full text-[10px]"
                                >
                                    Live data
                                </Badge>
                            </div>

                            <p className="mt-1 text-xs text-muted-foreground">
                                Revenue generated from completed
                                bookings for the selected period.
                            </p>
                        </div>

                        <Button
                            variant="ghost"
                            size="sm"
                            className="w-fit gap-1.5"
                            onClick={() => router.push("/admin/bookings")}
                        >
                            View bookings
                            <ArrowUpRight className="h-3.5 w-3.5" />
                        </Button>
                    </div>

                    <div className="border-t border-border bg-muted/20 px-5 py-4">
                        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-muted-foreground">
              <span>
                <strong className="font-semibold text-foreground">
                  {active.toursSold}
                </strong>{" "}
                  safaris sold
              </span>

                            <span>
                <strong className="font-semibold text-foreground">
                  {enquiryCount}
                </strong>{" "}
                                enquiries
              </span>

                            <span>
                <strong className="font-semibold text-foreground">
                  {formatCurrency(
                      active.actualRevenue,
                      "USD"
                  )}
                </strong>{" "}
                                actual revenue
              </span>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}