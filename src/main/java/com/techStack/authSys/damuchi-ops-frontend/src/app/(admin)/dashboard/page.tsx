"use client";

import {
    useCallback,
    useEffect,
    useMemo,
    useState,
} from "react";
import Link from "next/link";

import {
    AlertTriangle,
    ArrowRight,
    BookOpen,
    CalendarDays,
    CheckCircle2,
    ChevronLeft,
    ChevronRight,
    Clock,
    Map,
    Pencil,
    Plus,
    RefreshCw,
    Search,
    Star,
    StarOff,
    Trash2,
    TrendingUp,
    Trophy,
    Users,
} from "lucide-react";

import { toast } from "sonner";

import { bookingApi } from "@/lib/booking-api";
import { tourAdminApi } from "@/lib/tour-admin-api";
import { formatDate } from "@/lib/utils";

import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
    Card,
    CardContent,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";

import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";

import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";

import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

import type {
    Booking,
    BookingStats,
    ApiError,
} from "@/types/index-types";

import type {
    TourCategory,
    TourSummary,
} from "@/types/tour-admin";

const TOUR_PAGE_SIZE = 10;

const CATEGORIES: TourCategory[] = [
    "SAFARI",
    "DAY_TRIP",
    "BEACH",
    "MOUNTAIN",
    "CULTURAL",
    "ADVENTURE",
    "WILDLIFE",
    "CITY_TOUR",
    "PHOTOGRAPHY",
    "FAMILY",
    "CRUISE",
    "LUXURY",
    "HONEYMOON",
    "GROUP",
];

const CATEGORY_STYLES: Record<TourCategory, string> = {
    SAFARI:
        "bg-expedition-forest/10 text-expedition-forest",

    DAY_TRIP:
        "bg-teal-500/10 text-teal-600 dark:text-teal-400",

    BEACH:
        "bg-sky-500/10 text-sky-600 dark:text-sky-400",

    MOUNTAIN:
        "bg-stone-500/10 text-stone-600 dark:text-stone-400",

    CULTURAL:
        "bg-violet-500/10 text-violet-600 dark:text-violet-400",

    ADVENTURE:
        "bg-orange-500/10 text-orange-600 dark:text-orange-400",

    WILDLIFE:
        "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",

    CITY_TOUR:
        "bg-slate-500/10 text-slate-600 dark:text-slate-400",

    PHOTOGRAPHY:
        "bg-indigo-500/10 text-indigo-700 dark:text-indigo-400",

    FAMILY:
        "bg-pink-500/10 text-pink-600 dark:text-pink-400",

    CRUISE:
        "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",

    LUXURY:
        "bg-purple-500/10 text-purple-600 dark:text-purple-400",

    HONEYMOON:
        "bg-rose-500/10 text-rose-600 dark:text-rose-400",

    GROUP:
        "bg-amber-500/10 text-amber-600 dark:text-amber-400",
};

const BOOKING_STATUS_STYLES: Record<string, string> = {
    PENDING_PAYMENT:
        "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-400",

    CONFIRMED:
        "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-400",

    CANCELLED:
        "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-400",

    COMPLETED:
        "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-400",

    REFUNDED:
        "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-400",
};

function titleCase(value: string) {
    return value
        .toLowerCase()
        .replace(/_/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());
}

/* ============================================================
   STAT CARD
============================================================ */

function StatCard({
                      label,
                      value,
                      icon,
                      description,
                      accent = false,
                  }: {
    label: string;
    value: number | string;
    icon: React.ReactNode;
    description?: string;
    accent?: boolean;
}) {
    return (
        <Card
            className={
                accent
                    ? "border-primary/20 bg-gradient-to-br from-primary/[0.07] via-card to-card"
                    : ""
            }
        >
            <CardContent className="p-5">
                <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                        <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                            {label}
                        </p>

                        <p
                            className={`mt-2 font-display text-3xl font-semibold tracking-tight ${
                                accent ? "text-primary" : "text-foreground"
                            }`}
                        >
                            {value}
                        </p>

                        {description && (
                            <p className="mt-1 text-xs text-muted-foreground">
                                {description}
                            </p>
                        )}
                    </div>

                    <div
                        className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${
                            accent
                                ? "bg-primary/10 text-primary"
                                : "bg-muted text-muted-foreground"
                        }`}
                    >
                        {icon}
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}

/* ============================================================
   RECENT BOOKING
============================================================ */

function RecentBookingRow({
                              booking,
                          }: {
    booking: Booking;
}) {
    return (
        <Link
            href={`/staff/bookings/${booking.id}`}
            className="
        group flex items-center gap-4 rounded-lg px-3 py-3
        transition-colors hover:bg-muted/60
      "
        >
            <div className="
        flex h-9 w-9 shrink-0 items-center justify-center
        rounded-lg bg-muted text-muted-foreground
        transition-colors
        group-hover:bg-primary/10
        group-hover:text-primary
      ">
                <BookOpen className="h-4 w-4" />
            </div>

            <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium text-foreground">
                    {booking.tourName}
                </p>

                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                    {booking.customerName}
                    {" · "}
                    {formatDate(booking.tourDate, {
                        month: "short",
                        day: "numeric",
                        year: "numeric",
                    })}
                </p>
            </div>

            <Badge
                variant="outline"
                className={`
          hidden shrink-0 rounded-full text-[10px]
          font-medium sm:inline-flex
          ${BOOKING_STATUS_STYLES[booking.status] ?? ""}
        `}
            >
                {titleCase(booking.status)}
            </Badge>

            <ArrowRight
                className="
          h-4 w-4 shrink-0 text-muted-foreground/50
          transition-transform
          group-hover:translate-x-0.5
          group-hover:text-primary
        "
            />
        </Link>
    );
}

/* ============================================================
   QUICK ACTION
============================================================ */

function QuickAction({
                         href,
                         title,
                         description,
                         icon,
                     }: {
    href: string;
    title: string;
    description: string;
    icon: React.ReactNode;
}) {
    return (
        <Link
            href={href}
            className="
        group flex items-center gap-3 rounded-xl
        border border-border bg-card p-4
        transition-all
        hover:-translate-y-0.5
        hover:border-primary/30
        hover:shadow-sm
      "
        >
            <div
                className="
          flex h-10 w-10 shrink-0 items-center justify-center
          rounded-xl bg-muted text-muted-foreground
          transition-colors
          group-hover:bg-primary/10
          group-hover:text-primary
        "
            >
                {icon}
            </div>

            <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground">
                    {title}
                </p>

                <p className="mt-0.5 truncate text-xs text-muted-foreground">
                    {description}
                </p>
            </div>

            <ArrowRight
                className="
          h-4 w-4 text-muted-foreground/50
          transition-transform
          group-hover:translate-x-1
          group-hover:text-primary
        "
            />
        </Link>
    );
}

/* ============================================================
   PAGE
============================================================ */

export default function StaffDashboardPage() {
    /* ------------------------------------------------------------
       BOOKING STATE
    ------------------------------------------------------------- */

    const [stats, setStats] =
        useState<BookingStats | null>(null);

    const [recentBookings, setRecentBookings] =
        useState<Booking[]>([]);

    const [bookingLoading, setBookingLoading] =
        useState(true);

    const [bookingError, setBookingError] =
        useState<string | null>(null);

    /* ------------------------------------------------------------
       TOUR STATE
    ------------------------------------------------------------- */

    const [tours, setTours] =
        useState<TourSummary[]>([]);

    const [tourLoading, setTourLoading] =
        useState(true);

    const [tourError, setTourError] =
        useState<string | null>(null);

    const [page, setPage] =
        useState(0);

    const [totalPages, setTotalPages] =
        useState(0);

    const [totalElements, setTotalElements] =
        useState(0);

    const [search, setSearch] =
        useState("");

    const [categoryFilter, setCategoryFilter] =
        useState<TourCategory | "ALL">("ALL");

    const [deletingId, setDeletingId] =
        useState<string | null>(null);

    /* ============================================================
       LOAD BOOKINGS
    ============================================================ */

    const loadBookings = useCallback(async () => {
        setBookingLoading(true);
        setBookingError(null);

        try {
            /*
             * Keep stats and booking retrieval separate from the
             * enquire-button.tsx API so a enquire-button.tsx failure doesn't destroy the dashboard.
             */
            const [bookingStats, allBookings] =
                await Promise.all([
                    bookingApi.stats(),
                    bookingApi.all(),
                ]);

            setStats(bookingStats);

            /*
             * If backend ordering isn't guaranteed,
             * sorting here gives predictable recent results.
             *
             * Remove this sort if your Booking type does not
             * contain createdAt.
             */
            setRecentBookings(
                Array.isArray(allBookings)
                    ? allBookings.slice(0, 8)
                    : [],
            );
        } catch (error) {
            console.error(error);

            const message =
                (error as ApiError)?.message ||
                "Couldn't load booking activity.";

            setBookingError(message);
        } finally {
            setBookingLoading(false);
        }
    }, []);

    /* ============================================================
       LOAD TOURS
    ============================================================ */

    const loadTours = useCallback(
        async (targetPage = 0) => {
            setTourLoading(true);
            setTourError(null);

            try {
                const data = search.trim()
                    ? await tourAdminApi.searchTours(
                        search.trim(),
                        targetPage,
                        TOUR_PAGE_SIZE,
                    )
                    : await tourAdminApi.listTours({
                        page: targetPage,
                        size: TOUR_PAGE_SIZE,
                        category:
                            categoryFilter === "ALL"
                                ? undefined
                                : categoryFilter,
                    });

                setTours(
                    Array.isArray(data?.content)
                        ? data.content
                        : [],
                );

                setTotalPages(data?.totalPages ?? 0);
                setTotalElements(data?.totalElements ?? 0);
                setPage(targetPage);
            } catch (error) {
                console.error(error);

                const message =
                    (error as ApiError)?.message ||
                    "Couldn't load tours.";

                setTourError(message);
                setTours([]);

                toast.error(message);
            } finally {
                setTourLoading(false);
            }
        },
        [search, categoryFilter],
    );

    /* ============================================================
       INITIAL LOAD
    ============================================================ */

    useEffect(() => {
        loadBookings();
    }, [loadBookings]);

    useEffect(() => {
        loadTours(0);
    }, [loadTours]);

    /* ============================================================
       TOUR ACTIONS
    ============================================================ */

    async function handleToggleActive(
        tour: TourSummary,
    ) {
        try {
            await tourAdminApi.updateTour(tour.id, {
                active: !tour.active,
            });

            setTours((current) =>
                current.map((item) =>
                    item.id === tour.id
                        ? {
                            ...item,
                            active: !item.active,
                        }
                        : item,
                ),
            );

            toast.success(
                tour.active
                    ? `${tour.name} deactivated`
                    : `${tour.name} activated`,
            );
        } catch (error) {
            toast.error(
                (error as ApiError)?.message ||
                "Couldn't update enquire-button.tsx status.",
            );
        }
    }

    async function handleDelete(
        tour: TourSummary,
    ) {
        setDeletingId(tour.id);

        try {
            await tourAdminApi.deleteTour(tour.id);

            setTours((current) =>
                current.filter(
                    (item) => item.id !== tour.id,
                ),
            );

            setTotalElements((current) =>
                Math.max(0, current - 1),
            );

            toast.success(`${tour.name} removed`);
        } catch (error) {
            toast.error(
                (error as ApiError)?.message ||
                "Couldn't delete enquire-button.tsx.",
            );
        } finally {
            setDeletingId(null);
        }
    }

    /* ============================================================
       DERIVED DATA
    ============================================================ */

    const bookingOverview = useMemo(() => {
        const pending =
            stats?.pendingPayment ?? 0;

        const confirmed =
            stats?.confirmed ?? 0;

        const completed =
            stats?.completed ?? 0;

        const cancelled =
            stats?.cancelled ?? 0;

        return {
            pending,
            confirmed,
            completed,
            cancelled,
            active: pending + confirmed,
        };
    }, [stats]);

    const tourOverview = useMemo(
        () => ({
            visible: tours.length,

            active: tours.filter(
                (tour) => tour.active,
            ).length,

            featured: tours.filter(
                (tour) => tour.featured,
            ).length,
        }),
        [tours],
    );

    /* ============================================================
       RENDER
    ============================================================ */

    return (
        <div className="space-y-8 pb-10">

            {/* ========================================================
          PAGE HEADER
      ========================================================= */}

            <PageHeader
                eyebrow="Staff Operations"
                title="Operations dashboard"
                subtitle="Bookings, tours and daily operational activity in one place."
                action={
                    <div className="flex flex-wrap gap-2">
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                                loadBookings();
                                loadTours(page);
                            }}
                            disabled={
                                bookingLoading ||
                                tourLoading
                            }
                        >
                            <RefreshCw
                                className={`h-3.5 w-3.5 ${
                                    bookingLoading ||
                                    tourLoading
                                        ? "animate-spin"
                                        : ""
                                }`}
                            />

                            Refresh
                        </Button>

                        <Button
                            size="sm"
                            asChild
                        >
                            <Link href="/tours/new">
                                <Plus className="h-3.5 w-3.5" />
                                New tour
                            </Link>
                        </Button>
                    </div>
                }
            />

            {/* ========================================================
          BOOKING METRICS
      ========================================================= */}

            {bookingLoading ? (
                <div className="
          grid gap-4
          sm:grid-cols-2
          xl:grid-cols-4
        ">
                    {Array.from({
                        length: 4,
                    }).map((_, index) => (
                        <Skeleton
                            key={index}
                            className="h-[122px] rounded-xl"
                        />
                    ))}
                </div>
            ) : bookingError ? (
                <div className="
          flex items-center gap-3
          rounded-xl
          border border-destructive/20
          bg-destructive/5
          p-4
        ">
                    <AlertTriangle className="
            h-5 w-5 shrink-0
            text-destructive
          " />

                    <div className="flex-1">
                        <p className="
              text-sm font-medium
              text-foreground
            ">
                            Booking data unavailable
                        </p>

                        <p className="
              text-xs text-muted-foreground
            ">
                            {bookingError}
                        </p>
                    </div>

                    <Button
                        variant="outline"
                        size="sm"
                        onClick={loadBookings}
                    >
                        Retry
                    </Button>
                </div>
            ) : (
                <div className="
          grid gap-4
          sm:grid-cols-2
          xl:grid-cols-4
        ">
                    <StatCard
                        label="Active bookings"
                        value={bookingOverview.active}
                        description="Pending + confirmed"
                        icon={
                            <TrendingUp className="h-5 w-5" />
                        }
                        accent
                    />

                    <StatCard
                        label="Confirmed"
                        value={bookingOverview.confirmed}
                        description="Ready for travel"
                        icon={
                            <CheckCircle2 className="h-5 w-5" />
                        }
                    />

                    <StatCard
                        label="Pending payment"
                        value={bookingOverview.pending}
                        description="Awaiting payment"
                        icon={
                            <Clock className="h-5 w-5" />
                        }
                    />

                    <StatCard
                        label="Completed"
                        value={bookingOverview.completed}
                        description="Successfully completed"
                        icon={
                            <Trophy className="h-5 w-5" />
                        }
                    />
                </div>
            )}

            {/* ========================================================
          BOOKING ACTIVITY + ACTIONS
      ========================================================= */}

            <div className="
        grid gap-6
        xl:grid-cols-[minmax(0,1.6fr)_minmax(320px,0.8fr)]
      ">

                {/* Recent bookings */}

                <Card>
                    <CardHeader className="
            flex flex-row items-center
            justify-between
            space-y-0
            border-b border-border
            px-5 py-4
          ">
                        <div>
                            <CardTitle className="
                flex items-center gap-2
                text-base
              ">
                                <BookOpen className="
                  h-4 w-4 text-primary
                " />

                                Recent bookings
                            </CardTitle>

                            <p className="
                mt-1 text-xs
                text-muted-foreground
              ">
                                Latest customer booking activity
                            </p>
                        </div>

                        <Button
                            variant="ghost"
                            size="sm"
                            asChild
                        >
                            <Link href="/staff/bookings">
                                View all
                                <ArrowRight className="h-3.5 w-3.5" />
                            </Link>
                        </Button>
                    </CardHeader>

                    <CardContent className="p-2">
                        {bookingLoading ? (
                            <div className="space-y-2 p-2">
                                {Array.from({
                                    length: 5,
                                }).map((_, index) => (
                                    <Skeleton
                                        key={index}
                                        className="h-14 rounded-lg"
                                    />
                                ))}
                            </div>
                        ) : recentBookings.length === 0 ? (
                            <div className="
                py-12 text-center
              ">
                                <BookOpen className="
                  mx-auto h-8 w-8
                  text-muted-foreground/40
                " />

                                <p className="
                  mt-3 text-sm font-medium
                ">
                                    No bookings yet
                                </p>

                                <p className="
                  mt-1 text-xs
                  text-muted-foreground
                ">
                                    New booking activity will appear here.
                                </p>
                            </div>
                        ) : (
                            <div className="
                divide-y divide-border
              ">
                                {recentBookings.map(
                                    (booking) => (
                                        <RecentBookingRow
                                            key={booking.id}
                                            booking={booking}
                                        />
                                    ),
                                )}
                            </div>
                        )}
                    </CardContent>
                </Card>

                {/* Quick actions */}

                <div className="space-y-4">
                    <div>
                        <h2 className="
              text-sm font-semibold
              text-foreground
            ">
                            Quick actions
                        </h2>

                        <p className="
              mt-1 text-xs
              text-muted-foreground
            ">
                            Common daily operations
                        </p>
                    </div>

                    <div className="
            grid gap-3
            sm:grid-cols-2
            xl:grid-cols-1
          ">
                        <QuickAction
                            href="/staff/bookings"
                            title="All bookings"
                            description="Review and manage reservations"
                            icon={
                                <BookOpen className="h-4 w-4" />
                            }
                        />

                        <QuickAction
                            href="/staff/bookings?status=PENDING_PAYMENT"
                            title="Pending payments"
                            description={`${bookingOverview.pending} awaiting payment`}
                            icon={
                                <Clock className="h-4 w-4" />
                            }
                        />

                        <QuickAction
                            href="/staff/availability"
                            title="Availability"
                            description="Manage tour dates and capacity"
                            icon={
                                <CalendarDays className="h-4 w-4" />
                            }
                        />

                        <QuickAction
                            href="/tours"
                            title="Tour catalogue"
                            description={`${totalElements} tours currently registered`}
                            icon={
                                <Map className="h-4 w-4" />
                            }
                        />
                    </div>
                </div>
            </div>

            {/* ========================================================
          TOUR MANAGEMENT SECTION
      ========================================================= */}

            <section className="space-y-5">
                <div className="
          flex flex-col gap-4
          border-t border-border
          pt-8
          sm:flex-row
          sm:items-end
          sm:justify-between
        ">
                    <div>
                        <p className="
              text-[11px] font-semibold
              uppercase tracking-[0.14em]
              text-primary
            ">
                            Tour Operations
                        </p>

                        <h2 className="
              mt-1 font-display
              text-2xl font-semibold
              tracking-tight
            ">
                            Tour management
                        </h2>

                        <p className="
              mt-1 text-sm
              text-muted-foreground
            ">
                            Search, monitor and manage your tour catalogue.
                        </p>
                    </div>

                    <Button
                        size="sm"
                        asChild
                    >
                        <Link href="/tours/new">
                            <Plus className="h-4 w-4" />
                            Create tour
                        </Link>
                    </Button>
                </div>

                {/* Tour summary */}

                {!tourLoading &&
                    !tourError &&
                    totalElements > 0 && (
                        <div className="
              grid gap-3
              sm:grid-cols-3
            ">
                            <StatCard
                                label="Catalogue"
                                value={totalElements}
                                description="Total tours"
                                icon={
                                    <Map className="h-5 w-5" />
                                }
                            />

                            <StatCard
                                label="Active this page"
                                value={tourOverview.active}
                                description={`${tourOverview.visible} loaded`}
                                icon={
                                    <CheckCircle2 className="h-5 w-5" />
                                }
                            />

                            <StatCard
                                label="Featured"
                                value={tourOverview.featured}
                                description="Highlighted tours"
                                icon={
                                    <Star className="h-5 w-5" />
                                }
                            />
                        </div>
                    )}

                {/* Search & filter */}

                <div className="
          flex flex-col gap-3
          rounded-xl
          border border-border
          bg-card p-3
          sm:flex-row
          sm:items-center
        ">
                    <div className="
            relative flex-1
          ">
                        <Search className="
              absolute left-3 top-1/2
              h-4 w-4
              -translate-y-1/2
              text-muted-foreground
            " />

                        <Input
                            placeholder="Search tours by name, destination..."
                            className="
                border-none
                bg-muted/50
                pl-9 shadow-none
                focus-visible:ring-1
              "
                            value={search}
                            onChange={(event) =>
                                setSearch(event.target.value)
                            }
                        />
                    </div>

                    <Select
                        value={categoryFilter}
                        onValueChange={(value) =>
                            setCategoryFilter(
                                value as TourCategory | "ALL",
                            )
                        }
                    >
                        <SelectTrigger className="
              w-full
              border-none
              bg-muted/50
              shadow-none
              sm:w-48
            ">
                            <SelectValue placeholder="All categories" />
                        </SelectTrigger>

                        <SelectContent>
                            <SelectItem value="ALL">
                                All categories
                            </SelectItem>

                            {CATEGORIES.map(
                                (category) => (
                                    <SelectItem
                                        key={category}
                                        value={category}
                                    >
                                        {titleCase(category)}
                                    </SelectItem>
                                ),
                            )}
                        </SelectContent>
                    </Select>

                    <Button
                        variant="outline"
                        size="icon"
                        onClick={() => loadTours(page)}
                        disabled={tourLoading}
                        title="Refresh tours"
                    >
                        <RefreshCw
                            className={`h-4 w-4 ${
                                tourLoading
                                    ? "animate-spin"
                                    : ""
                            }`}
                        />
                    </Button>
                </div>

                {/* Tour content */}

                {tourLoading ? (
                    <div className="space-y-2">
                        {Array.from({
                            length: 6,
                        }).map((_, index) => (
                            <Skeleton
                                key={index}
                                className="h-16 rounded-xl"
                            />
                        ))}
                    </div>
                ) : tourError ? (
                    <EmptyState
                        icon={AlertTriangle}
                        title="Couldn't load tours"
                        description={tourError}
                    />
                ) : tours.length === 0 ? (
                    <EmptyState
                        icon={Map}
                        title="No tours found"
                        description={
                            search
                                ? "Try another search term or category."
                                : "Create your first enquire-button.tsx to start building the catalogue."
                        }
                    />
                ) : (
                    <>
                        {/* Desktop table */}

                        <div className="
              hidden overflow-hidden
              rounded-xl
              border border-border
              bg-card
              shadow-sm
              lg:block
            ">
                            <Table>
                                <TableHeader>
                                    <TableRow className="
                    hover:bg-transparent
                  ">
                                        <TableHead>
                                            Tour
                                        </TableHead>

                                        <TableHead>
                                            Category
                                        </TableHead>

                                        <TableHead>
                                            Destination
                                        </TableHead>

                                        <TableHead>
                                            Price
                                        </TableHead>

                                        <TableHead>
                                            Duration
                                        </TableHead>

                                        <TableHead>
                                            Rating
                                        </TableHead>

                                        <TableHead>
                                            Status
                                        </TableHead>

                                        <TableHead className="text-right">
                                            Actions
                                        </TableHead>
                                    </TableRow>
                                </TableHeader>

                                <TableBody>
                                    {tours.map((tour) => (
                                        <TableRow
                                            key={tour.id}
                                            className="group"
                                        >
                                            <TableCell>
                                                <div className="
                          flex items-center gap-2.5
                        ">
                                                    {tour.featured && (
                                                        <Star className="
                              h-3.5 w-3.5 shrink-0
                              fill-amber-400
                              text-amber-400
                            " />
                                                    )}

                                                    <div className="min-w-0">
                                                        <p className="
                              max-w-[220px]
                              truncate
                              font-medium
                            ">
                                                            {tour.name}
                                                        </p>

                                                        <p className="
                              max-w-[220px]
                              truncate
                              font-mono
                              text-[11px]
                              text-muted-foreground
                            ">
                                                            /{tour.slug}
                                                        </p>
                                                    </div>
                                                </div>
                                            </TableCell>

                                            <TableCell>
                                                <Badge
                                                    className={`
                            rounded-full
                            border-none
                            text-[10px]
                            font-medium
                            ${CATEGORY_STYLES[tour.category]}
                          `}
                                                >
                                                    {titleCase(
                                                        tour.category,
                                                    )}
                                                </Badge>
                                            </TableCell>

                                            <TableCell>
                                                <p className="text-xs">
                                                    {tour.destination}
                                                </p>

                                                <p className="
                          text-xs
                          text-muted-foreground
                        ">
                                                    {tour.country}
                                                </p>
                                            </TableCell>

                                            <TableCell className="
                        font-mono
                        text-xs font-medium
                      ">
                                                {tour.currency}{" "}
                                                {tour.price.toLocaleString()}
                                            </TableCell>

                                            <TableCell className="
                        text-xs
                        text-muted-foreground
                      ">
                                                {tour.durationDays}{" "}
                                                day
                                                {tour.durationDays !== 1
                                                    ? "s"
                                                    : ""}
                                            </TableCell>

                                            <TableCell>
                                                {tour.averageRating > 0 ? (
                                                    <span className="
                            inline-flex
                            items-center gap-1
                            text-xs
                          ">
                            <Star className="
                              h-3 w-3
                              fill-amber-400
                              text-amber-400
                            " />

                                                        {tour.averageRating.toFixed(
                                                            1,
                                                        )}
                          </span>
                                                ) : (
                                                    <span className="
                            text-xs
                            text-muted-foreground
                          ">
                            —
                          </span>
                                                )}
                                            </TableCell>

                                            <TableCell>
                                                <Badge
                                                    variant={
                                                        tour.active
                                                            ? "success"
                                                            : "outline"
                                                    }
                                                    className="
                            rounded-full
                            text-[10px]
                            font-medium
                          "
                                                >
                                                    {tour.active
                                                        ? "Active"
                                                        : "Inactive"}
                                                </Badge>
                                            </TableCell>

                                            <TableCell className="text-right">
                                                <div className="
                          flex justify-end gap-1
                          opacity-70
                          transition-opacity
                          group-hover:opacity-100
                        ">
                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        onClick={() =>
                                                            handleToggleActive(
                                                                tour,
                                                            )
                                                        }
                                                        title={
                                                            tour.active
                                                                ? "Deactivate"
                                                                : "Activate"
                                                        }
                                                    >
                                                        {tour.active ? (
                                                            <StarOff className="h-3.5 w-3.5" />
                                                        ) : (
                                                            <Star className="h-3.5 w-3.5" />
                                                        )}
                                                    </Button>

                                                    <Button
                                                        variant="ghost"
                                                        size="icon"
                                                        asChild
                                                        title="Edit tour"
                                                    >
                                                        <Link
                                                            href={`/tours/${tour.id}`}
                                                        >
                                                            <Pencil className="h-3.5 w-3.5" />
                                                        </Link>
                                                    </Button>

                                                    <AlertDialog>
                                                        <AlertDialogTrigger
                                                            asChild
                                                        >
                                                            <Button
                                                                variant="ghost"
                                                                size="icon"
                                                                disabled={
                                                                    deletingId ===
                                                                    tour.id
                                                                }
                                                                title="Delete tour"
                                                            >
                                                                <Trash2 className="
                                  h-3.5 w-3.5
                                  text-destructive
                                " />
                                                            </Button>
                                                        </AlertDialogTrigger>

                                                        <AlertDialogContent>
                                                            <AlertDialogHeader>
                                                                <AlertDialogTitle>
                                                                    Delete &quot;
                                                                    {tour.name}
                                                                    &quot;?
                                                                </AlertDialogTitle>

                                                                <AlertDialogDescription>
                                                                    This soft-deletes
                                                                    the tour. It will
                                                                    disappear from
                                                                    customer listings
                                                                    but is not
                                                                    permanently erased.
                                                                </AlertDialogDescription>
                                                            </AlertDialogHeader>

                                                            <AlertDialogFooter>
                                                                <AlertDialogCancel>
                                                                    Cancel
                                                                </AlertDialogCancel>

                                                                <AlertDialogAction
                                                                    onClick={() =>
                                                                        handleDelete(
                                                                            tour,
                                                                        )
                                                                    }
                                                                    className="
                                    bg-destructive
                                    text-destructive-foreground
                                    hover:bg-destructive/90
                                  "
                                                                >
                                                                    Delete tour
                                                                </AlertDialogAction>
                                                            </AlertDialogFooter>
                                                        </AlertDialogContent>
                                                    </AlertDialog>
                                                </div>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>

                        {/* Mobile enquire-button.tsx cards */}

                        <div className="
              grid gap-3 lg:hidden
            ">
                            {tours.map((tour) => (
                                <Card key={tour.id}>
                                    <CardContent className="p-4">
                                        <div className="
                      flex items-start
                      justify-between gap-3
                    ">
                                            <div className="min-w-0">
                                                <div className="
                          flex items-center gap-2
                        ">
                                                    {tour.featured && (
                                                        <Star className="
                              h-3.5 w-3.5
                              fill-amber-400
                              text-amber-400
                            " />
                                                    )}

                                                    <p className="
                            truncate
                            font-medium
                          ">
                                                        {tour.name}
                                                    </p>
                                                </div>

                                                <p className="
                          mt-1 text-xs
                          text-muted-foreground
                        ">
                                                    {tour.destination}
                                                    {" · "}
                                                    {tour.durationDays}d
                                                </p>
                                            </div>

                                            <Badge
                                                variant={
                                                    tour.active
                                                        ? "success"
                                                        : "outline"
                                                }
                                                className="
                          shrink-0
                          rounded-full
                          text-[10px]
                        "
                                            >
                                                {tour.active
                                                    ? "Active"
                                                    : "Inactive"}
                                            </Badge>
                                        </div>

                                        <div className="
                      mt-4 flex
                      items-center
                      justify-between
                    ">
                                            <div>
                                                <Badge
                                                    className={`
                            rounded-full
                            border-none
                            text-[10px]
                            ${CATEGORY_STYLES[tour.category]}
                          `}
                                                >
                                                    {titleCase(
                                                        tour.category,
                                                    )}
                                                </Badge>

                                                <p className="
                          mt-2 font-mono
                          text-sm font-semibold
                        ">
                                                    {tour.currency}{" "}
                                                    {tour.price.toLocaleString()}
                                                </p>
                                            </div>

                                            <Button
                                                variant="outline"
                                                size="sm"
                                                asChild
                                            >
                                                <Link
                                                    href={`/tours/${tour.id}`}
                                                >
                                                    Manage
                                                    <ArrowRight className="h-3.5 w-3.5" />
                                                </Link>
                                            </Button>
                                        </div>
                                    </CardContent>
                                </Card>
                            ))}
                        </div>

                        {/* Pagination */}

                        {totalPages > 1 && (
                            <div className="
                flex items-center
                justify-between pt-2
              ">
                <span className="
                  text-xs
                  text-muted-foreground
                ">
                  Page {page + 1} of{" "}
                    {totalPages}
                    {" · "}
                    {totalElements} tours
                </span>

                                <div className="flex gap-2">
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() =>
                                            loadTours(page - 1)
                                        }
                                        disabled={
                                            page === 0 ||
                                            tourLoading
                                        }
                                    >
                                        <ChevronLeft className="h-3.5 w-3.5" />
                                        Previous
                                    </Button>

                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() =>
                                            loadTours(page + 1)
                                        }
                                        disabled={
                                            page + 1 >=
                                            totalPages ||
                                            tourLoading
                                        }
                                    >
                                        Next
                                        <ChevronRight className="h-3.5 w-3.5" />
                                    </Button>
                                </div>
                            </div>
                        )}
                    </>
                )}
            </section>
        </div>
    );
}