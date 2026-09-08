"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
    Users,
    User,
    Search,
    RefreshCw,
    ChevronLeft,
    ChevronRight,
    Mail,
    Phone,
    CalendarDays,
    MapPin,
    Eye,
    X,
    BookOpen,
    TrendingUp,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import {
    Sheet,
    SheetContent,
    SheetDescription,
    SheetFooter,
    SheetHeader,
    SheetTitle,
} from "@/components/ui/sheet";
import { Separator } from "@/components/ui/separator";

import type { ApiError } from "@/types";

/* ============================================================
 * Types
 * ============================================================ */

export interface Customer {
    id: string;
    firstName?: string;
    lastName?: string;
    name?: string;

    email: string;
    phone?: string;

    country?: string;
    city?: string;

    totalBookings?: number;
    completedBookings?: number;
    cancelledBookings?: number;
    totalSpent?: number;

    lastBookingDate?: string;
    createdAt?: string;

    active?: boolean;
}

interface CustomerPageResponse {
    content: Customer[];
    totalElements: number;
    totalPages: number;
    number?: number;
}

/* ============================================================
 * API
 *
 * Replace this import/implementation with your actual
 * customer API once available.
 * ============================================================ */

import { customerApi } from "@/lib/customer-api";

const PAGE_SIZE = 20;

/* ============================================================
 * Helpers
 * ============================================================ */

function getCustomerName(customer: Customer) {
    if (customer.name?.trim()) {
        return customer.name;
    }

    const fullName = [customer.firstName, customer.lastName]
        .filter(Boolean)
        .join(" ")
        .trim();

    return fullName || "Unnamed customer";
}

function getInitials(customer: Customer) {
    const name = getCustomerName(customer);

    return name
        .split(/\s+/)
        .slice(0, 2)
        .map((part) => part.charAt(0).toUpperCase())
        .join("");
}

function formatDate(iso?: string) {
    if (!iso) return "—";

    const date = new Date(iso);

    if (Number.isNaN(date.getTime())) return "—";

    return date.toLocaleDateString(undefined, {
        day: "numeric",
        month: "short",
        year: "numeric",
    });
}

function formatDateTime(iso?: string) {
    if (!iso) return "—";

    const date = new Date(iso);

    if (Number.isNaN(date.getTime())) return "—";

    return date.toLocaleString(undefined, {
        day: "numeric",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    });
}

function formatCurrency(value?: number) {
    if (value == null) return "—";

    return new Intl.NumberFormat("en-KE", {
        style: "currency",
        currency: "KES",
        maximumFractionDigits: 0,
    }).format(value);
}

/* ============================================================
 * Customer Avatar
 * ============================================================ */

function CustomerAvatar({ customer }: { customer: Customer }) {
    return (
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-expedition-forest/10 text-xs font-semibold text-expedition-forest">
            {getInitials(customer)}
        </div>
    );
}

/* ============================================================
 * Stat Card
 * ============================================================ */

function CustomerStat({
                          label,
                          value,
                          icon: Icon,
                          description,
                      }: {
    label: string;
    value: string | number;
    icon: React.ElementType;
    description?: string;
}) {
    return (
        <Card className="border-border/70 shadow-none">
            <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3">
                    <div>
                        <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                            {label}
                        </p>

                        <p className="mt-1 font-display text-2xl font-semibold tracking-tight">
                            {value}
                        </p>

                        {description && (
                            <p className="mt-1 text-xs text-muted-foreground">
                                {description}
                            </p>
                        )}
                    </div>

                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}

/* ============================================================
 * Loading Table
 * ============================================================ */

function CustomerTableSkeleton() {
    return (
        <div className="overflow-hidden rounded-xl border border-border bg-card">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Customer</TableHead>
                        <TableHead>Contact</TableHead>
                        <TableHead>Location</TableHead>
                        <TableHead>Bookings</TableHead>
                        <TableHead>Last booking</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead className="text-right">Joined</TableHead>
                    </TableRow>
                </TableHeader>

                <TableBody>
                    {Array.from({ length: 7 }).map((_, index) => (
                        <TableRow key={index}>
                            <TableCell>
                                <div className="flex items-center gap-3">
                                    <Skeleton className="h-9 w-9 rounded-full" />

                                    <div className="space-y-1.5">
                                        <Skeleton className="h-4 w-32" />
                                        <Skeleton className="h-3 w-40" />
                                    </div>
                                </div>
                            </TableCell>

                            <TableCell>
                                <Skeleton className="h-4 w-32" />
                            </TableCell>

                            <TableCell>
                                <Skeleton className="h-4 w-24" />
                            </TableCell>

                            <TableCell>
                                <Skeleton className="h-4 w-12" />
                            </TableCell>

                            <TableCell>
                                <Skeleton className="h-4 w-24" />
                            </TableCell>

                            <TableCell>
                                <Skeleton className="h-5 w-16 rounded-full" />
                            </TableCell>

                            <TableCell className="text-right">
                                <Skeleton className="ml-auto h-4 w-24" />
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </div>
    );
}

/* ============================================================
 * Mobile Customer Card
 * ============================================================ */

function CustomerMobileCard({
                                customer,
                                onOpen,
                            }: {
    customer: Customer;
    onOpen: () => void;
}) {
    return (
        <button
            type="button"
            onClick={onOpen}
            className="w-full rounded-xl border border-border bg-card p-4 text-left shadow-sm transition-colors hover:bg-muted/30"
        >
            <div className="flex items-start gap-3">
                <CustomerAvatar customer={customer} />

                <div className="min-w-0 flex-1">
                    <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                            <p className="truncate font-medium">
                                {getCustomerName(customer)}
                            </p>

                            <p className="truncate text-xs text-muted-foreground">
                                {customer.email}
                            </p>
                        </div>

                        <Badge
                            variant={customer.active === false ? "secondary" : "success"}
                            className="shrink-0 rounded-full text-[10px]"
                        >
                            {customer.active === false ? "Inactive" : "Active"}
                        </Badge>
                    </div>

                    <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
                        <div>
                            <p className="text-muted-foreground">Bookings</p>
                            <p className="mt-0.5 font-medium">
                                {customer.totalBookings ?? 0}
                            </p>
                        </div>

                        <div>
                            <p className="text-muted-foreground">Last booking</p>
                            <p className="mt-0.5 font-medium">
                                {formatDate(customer.lastBookingDate)}
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </button>
    );
}

/* ============================================================
 * Main Page
 * ============================================================ */

export default function CustomersPage() {
    const [customers, setCustomers] = useState<Customer[]>([]);

    const [page, setPage] = useState(0);
    const [totalPages, setTotalPages] = useState(0);
    const [totalElements, setTotalElements] = useState(0);

    const [isLoading, setIsLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);

    const [search, setSearch] = useState("");

    const [selected, setSelected] = useState<Customer | null>(null);

    /* ==========================================================
     * Load customers
     * ========================================================== */

    const load = useCallback(
        async (targetPage = 0) => {
            setIsLoading(true);
            setLoadError(null);

            try {
                const data = search.trim()
                    ? await customerApi.searchCustomers(
                        search.trim(),
                        targetPage,
                        PAGE_SIZE
                    )
                    : await customerApi.listCustomers(
                        targetPage,
                        PAGE_SIZE
                    );

                setCustomers(
                    Array.isArray(data?.content)
                        ? data.content
                        : []
                );

                setTotalPages(data?.totalPages ?? 0);
                setTotalElements(data?.totalElements ?? 0);
                setPage(targetPage);
            } catch (err) {
                const message =
                    (err as ApiError)?.message ||
                    "Couldn't load customers.";

                setLoadError(message);
                setCustomers([]);

                toast.error(message);
            } finally {
                setIsLoading(false);
            }
        },
        [search]
    );

    useEffect(() => {
        const timer = window.setTimeout(() => {
            load(0);
        }, 300);

        return () => window.clearTimeout(timer);
    }, [load]);

    /* ==========================================================
     * Page statistics
     * ========================================================== */

    const statistics = useMemo(() => {
        const active = customers.filter(
            (customer) => customer.active !== false
        ).length;

        const customersWithBookings = customers.filter(
            (customer) => (customer.totalBookings ?? 0) > 0
        ).length;

        const totalBookings = customers.reduce(
            (sum, customer) => sum + (customer.totalBookings ?? 0),
            0
        );

        return {
            active,
            customersWithBookings,
            totalBookings,
        };
    }, [customers]);

    /* ==========================================================
     * Render
     * ========================================================== */

    return (
        <div className="space-y-7">
            {/* ======================================================
       * Header
       * ====================================================== */}

            <PageHeader
                eyebrow="Customer Management"
                title="Customers"
                subtitle={
                    isLoading
                        ? "Loading customer records…"
                        : loadError
                            ? "Unable to load customers"
                            : `${totalElements} customer${
                                totalElements !== 1 ? "s" : ""
                            }`
                }
                action={
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => load(page)}
                        disabled={isLoading}
                    >
                        <RefreshCw
                            className={`h-3.5 w-3.5 ${
                                isLoading ? "animate-spin" : ""
                            }`}
                        />

                        Refresh
                    </Button>
                }
            />

            {/* ======================================================
       * Stats
       * ====================================================== */}

            {!isLoading && !loadError && customers.length > 0 && (
                <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                    <CustomerStat
                        label="Customers"
                        value={totalElements}
                        icon={Users}
                        description="Total registered"
                    />

                    <CustomerStat
                        label="Active"
                        value={statistics.active}
                        icon={User}
                        description="On this page"
                    />

                    <CustomerStat
                        label="Booked"
                        value={statistics.customersWithBookings}
                        icon={BookOpen}
                        description="Customers with bookings"
                    />

                    <CustomerStat
                        label="Bookings"
                        value={statistics.totalBookings}
                        icon={TrendingUp}
                        description="Across this page"
                    />
                </div>
            )}

            {/* ======================================================
       * Search
       * ====================================================== */}

            <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-3 sm:flex-row sm:items-center">
                <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />

                    <Input
                        value={search}
                        onChange={(event) => setSearch(event.target.value)}
                        placeholder="Search customers by name, email or phone…"
                        className="border-none bg-muted/50 pl-9 shadow-none focus-visible:ring-1"
                    />
                </div>

                {search && (
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setSearch("")}
                        className="shrink-0"
                    >
                        <X className="h-3.5 w-3.5" />
                        Clear
                    </Button>
                )}
            </div>

            {/* ======================================================
       * Error
       * ====================================================== */}

            {loadError && !isLoading && (
                <Card className="border-destructive/30 bg-destructive/5 shadow-none">
                    <CardContent className="flex flex-col items-center justify-center gap-3 py-10 text-center">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-destructive/10">
                            <Users className="h-5 w-5 text-destructive" />
                        </div>

                        <div>
                            <p className="font-medium">
                                Couldn't load customers
                            </p>

                            <p className="mt-1 text-sm text-muted-foreground">
                                {loadError}
                            </p>
                        </div>

                        <Button
                            variant="outline"
                            size="sm"
                            onClick={() => load(page)}
                        >
                            Try again
                        </Button>
                    </CardContent>
                </Card>
            )}

            {/* ======================================================
       * Loading
       * ====================================================== */}

            {isLoading && <CustomerTableSkeleton />}

            {/* ======================================================
       * Empty
       * ====================================================== */}

            {!isLoading &&
                !loadError &&
                customers.length === 0 && (
                    <EmptyState
                        icon={Users}
                        title={
                            search
                                ? "No customers found"
                                : "No customers yet"
                        }
                        description={
                            search
                                ? `No customer matches "${search}". Try another search.`
                                : "Customers will appear here once they register or make a booking."
                        }
                    />
                )}

            {/* ======================================================
       * Desktop Table
       * ====================================================== */}

            {!isLoading &&
                !loadError &&
                customers.length > 0 && (
                    <>
                        <div className="hidden overflow-hidden rounded-xl border border-border bg-card shadow-sm md:block">
                            <Table>
                                <TableHeader>
                                    <TableRow className="hover:bg-transparent">
                                        <TableHead>Customer</TableHead>
                                        <TableHead>Contact</TableHead>
                                        <TableHead>Location</TableHead>
                                        <TableHead>Bookings</TableHead>
                                        <TableHead>Last booking</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead className="text-right">
                                            Joined
                                        </TableHead>
                                    </TableRow>
                                </TableHeader>

                                <TableBody>
                                    {customers.map((customer) => (
                                        <TableRow
                                            key={customer.id}
                                            className="group cursor-pointer"
                                            onClick={() => setSelected(customer)}
                                        >
                                            {/* Customer */}
                                            <TableCell>
                                                <div className="flex items-center gap-3">
                                                    <CustomerAvatar customer={customer} />

                                                    <div className="min-w-0">
                                                        <p className="font-medium leading-tight">
                                                            {getCustomerName(customer)}
                                                        </p>

                                                        <p className="mt-0.5 max-w-[220px] truncate text-xs text-muted-foreground">
                                                            {customer.email}
                                                        </p>
                                                    </div>
                                                </div>
                                            </TableCell>

                                            {/* Contact */}
                                            <TableCell>
                                                <div className="space-y-1 text-xs">
                                                    <div className="flex items-center gap-1.5">
                                                        <Mail className="h-3 w-3 text-muted-foreground" />

                                                        <span className="max-w-[190px] truncate">
                              {customer.email}
                            </span>
                                                    </div>

                                                    {customer.phone && (
                                                        <div className="flex items-center gap-1.5 text-muted-foreground">
                                                            <Phone className="h-3 w-3" />
                                                            {customer.phone}
                                                        </div>
                                                    )}
                                                </div>
                                            </TableCell>

                                            {/* Location */}
                                            <TableCell>
                                                {customer.city || customer.country ? (
                                                    <div className="flex items-center gap-1.5 text-xs">
                                                        <MapPin className="h-3.5 w-3.5 text-muted-foreground" />

                                                        <span>
                              {[customer.city, customer.country]
                                  .filter(Boolean)
                                  .join(", ")}
                            </span>
                                                    </div>
                                                ) : (
                                                    <span className="text-xs text-muted-foreground">
                            —
                          </span>
                                                )}
                                            </TableCell>

                                            {/* Bookings */}
                                            <TableCell>
                                                <div className="inline-flex items-center gap-1.5 text-sm">
                                                    <BookOpen className="h-3.5 w-3.5 text-muted-foreground" />

                                                    <span className="font-medium">
                            {customer.totalBookings ?? 0}
                          </span>
                                                </div>
                                            </TableCell>

                                            {/* Last booking */}
                                            <TableCell>
                        <span className="text-xs text-muted-foreground">
                          {formatDate(customer.lastBookingDate)}
                        </span>
                                            </TableCell>

                                            {/* Status */}
                                            <TableCell>
                                                <Badge
                                                    variant={
                                                        customer.active === false
                                                            ? "secondary"
                                                            : "success"
                                                    }
                                                    className="rounded-full text-[10px] font-medium"
                                                >
                                                    {customer.active === false
                                                        ? "Inactive"
                                                        : "Active"}
                                                </Badge>
                                            </TableCell>

                                            {/* Joined */}
                                            <TableCell className="text-right">
                                                <div className="flex items-center justify-end gap-2">
                          <span className="text-xs text-muted-foreground">
                            {formatDate(customer.createdAt)}
                          </span>

                                                    <Eye className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                                                </div>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </div>

                        {/* ==================================================
             * Mobile Cards
             * ================================================== */}

                        <div className="grid gap-3 md:hidden">
                            {customers.map((customer) => (
                                <CustomerMobileCard
                                    key={customer.id}
                                    customer={customer}
                                    onOpen={() => setSelected(customer)}
                                />
                            ))}
                        </div>

                        {/* ==================================================
             * Pagination
             * ================================================== */}

                        {totalPages > 1 && (
                            <div className="flex flex-col gap-3 pt-2 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-xs text-muted-foreground">
                  Showing{" "}
                    <span className="font-medium text-foreground">
                    {page * PAGE_SIZE + 1}
                  </span>{" "}
                    –{" "}
                    <span className="font-medium text-foreground">
                    {Math.min(
                        (page + 1) * PAGE_SIZE,
                        totalElements
                    )}
                  </span>{" "}
                    of{" "}
                    <span className="font-medium text-foreground">
                    {totalElements}
                  </span>
                </span>

                                <div className="flex gap-2">
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => load(page - 1)}
                                        disabled={page === 0 || isLoading}
                                    >
                                        <ChevronLeft className="h-3.5 w-3.5" />
                                        Previous
                                    </Button>

                                    <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => load(page + 1)}
                                        disabled={
                                            page + 1 >= totalPages ||
                                            isLoading
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

            {/* ======================================================
       * Customer Detail Sheet
       * ====================================================== */}

            <Sheet
                open={!!selected}
                onOpenChange={(open) => {
                    if (!open) setSelected(null);
                }}
            >
                <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
                    {selected && (
                        <>
                            <SheetHeader>
                                <div className="flex items-center gap-3">
                                    <CustomerAvatar customer={selected} />

                                    <div className="min-w-0">
                                        <SheetTitle className="font-display">
                                            {getCustomerName(selected)}
                                        </SheetTitle>

                                        <SheetDescription className="truncate">
                                            {selected.email}
                                        </SheetDescription>
                                    </div>
                                </div>
                            </SheetHeader>

                            <div className="space-y-6 py-6">
                                {/* Profile */}
                                <section className="space-y-3">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                        Customer profile
                                    </p>

                                    <div className="rounded-xl border border-border bg-muted/20 p-4">
                                        <div className="space-y-3 text-sm">
                                            <div className="flex items-center justify-between gap-4">
                        <span className="text-muted-foreground">
                          Email
                        </span>

                                                <span className="truncate font-medium">
                          {selected.email}
                        </span>
                                            </div>

                                            {selected.phone && (
                                                <div className="flex items-center justify-between gap-4">
                          <span className="text-muted-foreground">
                            Phone
                          </span>

                                                    <span className="font-medium">
                            {selected.phone}
                          </span>
                                                </div>
                                            )}

                                            {(selected.city ||
                                                selected.country) && (
                                                <div className="flex items-center justify-between gap-4">
                          <span className="text-muted-foreground">
                            Location
                          </span>

                                                    <span className="font-medium">
                            {[selected.city, selected.country]
                                .filter(Boolean)
                                .join(", ")}
                          </span>
                                                </div>
                                            )}

                                            <div className="flex items-center justify-between gap-4">
                        <span className="text-muted-foreground">
                          Status
                        </span>

                                                <Badge
                                                    variant={
                                                        selected.active === false
                                                            ? "secondary"
                                                            : "success"
                                                    }
                                                    className="rounded-full text-[10px]"
                                                >
                                                    {selected.active === false
                                                        ? "Inactive"
                                                        : "Active"}
                                                </Badge>
                                            </div>
                                        </div>
                                    </div>
                                </section>

                                <Separator />

                                {/* Booking Summary */}
                                <section className="space-y-3">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                        Booking activity
                                    </p>

                                    <div className="grid grid-cols-2 gap-3">
                                        <Card className="border-none bg-muted/40 shadow-none">
                                            <CardContent className="p-4">
                                                <p className="text-xs text-muted-foreground">
                                                    Total bookings
                                                </p>

                                                <p className="mt-1 font-display text-2xl font-semibold">
                                                    {selected.totalBookings ?? 0}
                                                </p>
                                            </CardContent>
                                        </Card>

                                        <Card className="border-none bg-emerald-500/5 shadow-none">
                                            <CardContent className="p-4">
                                                <p className="text-xs text-muted-foreground">
                                                    Completed
                                                </p>

                                                <p className="mt-1 font-display text-2xl font-semibold text-emerald-600 dark:text-emerald-400">
                                                    {selected.completedBookings ?? 0}
                                                </p>
                                            </CardContent>
                                        </Card>

                                        <Card className="border-none bg-amber-500/5 shadow-none">
                                            <CardContent className="p-4">
                                                <p className="text-xs text-muted-foreground">
                                                    Last booking
                                                </p>

                                                <p className="mt-1 text-sm font-semibold">
                                                    {formatDate(
                                                        selected.lastBookingDate
                                                    )}
                                                </p>
                                            </CardContent>
                                        </Card>

                                        <Card className="border-none bg-expedition-forest/5 shadow-none">
                                            <CardContent className="p-4">
                                                <p className="text-xs text-muted-foreground">
                                                    Total spent
                                                </p>

                                                <p className="mt-1 text-sm font-semibold">
                                                    {formatCurrency(
                                                        selected.totalSpent
                                                    )}
                                                </p>
                                            </CardContent>
                                        </Card>
                                    </div>
                                </section>

                                <Separator />

                                {/* Customer timeline */}
                                <section className="space-y-3">
                                    <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                                        Customer history
                                    </p>

                                    <div className="space-y-4">
                                        <div className="flex gap-3">
                                            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                                                <User className="h-3.5 w-3.5 text-muted-foreground" />
                                            </div>

                                            <div>
                                                <p className="text-sm font-medium">
                                                    Customer registered
                                                </p>

                                                <p className="text-xs text-muted-foreground">
                                                    {formatDateTime(selected.createdAt)}
                                                </p>
                                            </div>
                                        </div>

                                        {selected.lastBookingDate && (
                                            <div className="flex gap-3">
                                                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-expedition-forest/10">
                                                    <CalendarDays className="h-3.5 w-3.5 text-expedition-forest" />
                                                </div>

                                                <div>
                                                    <p className="text-sm font-medium">
                                                        Most recent booking
                                                    </p>

                                                    <p className="text-xs text-muted-foreground">
                                                        {formatDateTime(
                                                            selected.lastBookingDate
                                                        )}
                                                    </p>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </section>
                            </div>

                            <SheetFooter>
                                <Button
                                    variant="outline"
                                    onClick={() => setSelected(null)}
                                    className="w-full"
                                >
                                    Close
                                </Button>
                            </SheetFooter>
                        </>
                    )}
                </SheetContent>
            </Sheet>
        </div>
    );
}