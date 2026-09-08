"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import Link from "next/link";
import { motion } from "framer-motion";

import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  Eye,
  Map,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  Users,
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

import { Separator } from "@/components/ui/separator";

import { tourAdminApi } from "@/lib/tour-admin-api";
import { formatCurrency } from "@/lib/utils";

import type {
  ApiError,
} from "@/types/index-types";

import type { TourCategory, TourSummary } from "@/types/tour-admin";

const PAGE_SIZE = 20;

const CATEGORIES: {
  value: TourCategory | "ALL";
  label: string;
}[] = [
  { value: "ALL", label: "All categories" },
  { value: "WILDLIFE", label: "Wildlife" },
  { value: "MOUNTAIN", label: "Mountain" },
  { value: "BEACH", label: "Beach" },
  { value: "CULTURAL", label: "Cultural" },
  { value: "ADVENTURE", label: "Adventure" },
  { value: "PHOTOGRAPHY", label: "Photography" },
  { value: "FAMILY", label: "Family" },
  { value: "LUXURY", label: "Luxury" },
];

const CATEGORY_STYLES: Partial<
  Record<TourCategory, string>
> = {
  WILDLIFE:
    "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  MOUNTAIN:
    "bg-stone-500/10 text-stone-700 dark:text-stone-400",
  BEACH:
    "bg-sky-500/10 text-sky-700 dark:text-sky-400",
  CULTURAL:
    "bg-violet-500/10 text-violet-700 dark:text-violet-400",
  ADVENTURE:
    "bg-orange-500/10 text-orange-700 dark:text-orange-400",
  PHOTOGRAPHY:
    "bg-indigo-500/10 text-indigo-700 dark:text-indigo-400",
  FAMILY:
    "bg-pink-500/10 text-pink-700 dark:text-pink-400",
  LUXURY:
    "bg-amber-500/10 text-amber-700 dark:text-amber-400",
};

function titleCase(value: string) {
  return value
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function StatCard({
  label,
  value,
  description,
  icon: Icon,
  accent = false,
}: {
  label: string;
  value: number | string;
  description: string;
  icon: React.ElementType;
  accent?: boolean;
}) {
  return (
    <Card
      className={
        accent
          ? "border-primary/20 bg-primary/[0.04]"
          : ""
      }
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              {label}
            </p>

            <p
              className={`mt-1 font-display text-2xl font-semibold ${
                accent ? "text-primary" : ""
              }`}
            >
              {value}
            </p>

            <p className="mt-0.5 text-[11px] text-muted-foreground">
              {description}
            </p>
          </div>

          <div
            className={`flex h-9 w-9 items-center justify-center rounded-lg ${
              accent
                  ? "bg-primary/10 text-primary"
                  : "bg-muted text-muted-foreground"
            }`}
          >
            <Icon className="h-4 w-4" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatusBadge({
  active,
}: {
  active: boolean;
}) {
  return (
    <Badge
      variant="outline"
      className={
        active
          ? "rounded-full border-emerald-200 bg-emerald-50 text-[10px] font-medium text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-400"
          : "rounded-full border-muted bg-muted/50 text-[10px] font-medium text-muted-foreground"
      }
    >
      <span
        className={`mr-1.5 h-1.5 w-1.5 rounded-full ${
          active
              ? "bg-emerald-500"
              : "bg-muted-foreground/50"
        }`}
      />
      {active ? "Active" : "Inactive"}
    </Badge>
  );
}

export default function StaffToursPage() {

  const [tours, setTours] = useState<TourSummary[]>([]);

  const [total, setTotal] =
    useState(0);

  const [page, setPage] =
    useState(0);

  const [isLoading, setIsLoading] =
    useState(true);

  const [loadError, setLoadError] =
    useState<string | null>(null);

  const [search, setSearch] =
    useState("");

  const [category, setCategory] =
    useState<TourCategory | "ALL">("ALL");

  const [selected, setSelected] = useState<TourSummary | null>(null);

  const [confirmingDelete, setConfirmingDelete] =
    useState(false);

  const [isProcessing, setIsProcessing] =
    useState(false);

  const load = useCallback(
      async (targetPage = 0) => {
        setIsLoading(true);
        setLoadError(null);

        try {
          const res = await tourAdminApi.listTours({
            page: targetPage,
            size: PAGE_SIZE,
            category: category === "ALL" ? undefined : category,
          });

          setTours(Array.isArray(res?.content) ? res.content : []);
          setTotal(res?.totalElements ?? 0);
          setPage(targetPage);
        } catch (err) {
          const message = (err as ApiError)?.message || "Couldn't load tours.";
          setLoadError(message);
          setTours([]);
          toast.error(message);
        } finally {
          setIsLoading(false);
        }
      },
      [category],
  );

  useEffect(() => {
    load(0);
  }, [load]);

  const filtered = useMemo(() => {
    const query =
      search.trim().toLowerCase();

    if (!query) {
      return tours;
    }

    return tours.filter((tour) =>
      [
        tour.name,
        tour.destination,
        tour.category,
      ]
        .filter(Boolean)
        .some((value) =>
          String(value)
            .toLowerCase()
            .includes(query),
        ),
    );
  }, [tours, search]);

  const totalPages =
    Math.ceil(total / PAGE_SIZE);

  const pageStats =
    useMemo(() => {
      return {
        active:
          tours.filter(
            (tour) => tour.active,
          ).length,

        inactive:
          tours.filter(
            (tour) => !tour.active,
          ).length,

      };
    }, [tours]);

  function openDetail(tour: TourSummary) {
    setSelected(tour);
    setConfirmingDelete(false);
  }

  function closeDetail() {
    setSelected(null);
    setConfirmingDelete(false);
  }

  async function handlePublish() {
    if (!selected) return;

    setIsProcessing(true);

    try {
      const updated =
        await tourAdminApi.publishTour(
          selected.id,
        );

      const merged = {
        ...selected,
        ...updated,
      };

      setTours((prev) =>
        prev.map((tour) =>
          tour.id === selected.id
            ? merged
            : tour,
        ),
      );

      setSelected(merged);

      toast.success(
        `"${selected.name}" published.`,
      );
    } catch (err) {
      toast.error(
        (err as ApiError)?.message ||
          "Couldn't publish enquire-button.tsx.",
      );
    } finally {
      setIsProcessing(false);
    }
  }

  async function handleDelete() {
    if (!selected) return;

    if (!confirmingDelete) {
      setConfirmingDelete(true);
      return;
    }

    setIsProcessing(true);

    try {
      await tourAdminApi.deleteTour(
        selected.id,
      );

      setTours((prev) =>
        prev.filter(
          (tour) =>
            tour.id !== selected.id,
        ),
      );

      setTotal((prev) =>
        Math.max(0, prev - 1),
      );

      toast.success(
        `"${selected.name}" deleted.`,
      );

      closeDetail();
    } catch (err) {
      toast.error(
        (err as ApiError)?.message ||
          "Couldn't delete enquire-button.tsx.",
      );
    } finally {
      setIsProcessing(false);
    }
  }

  return (
    <div className="space-y-7 pb-10">
      <PageHeader
        eyebrow="Tour Operations"
        title="Tour catalogue"
        subtitle={
          isLoading
            ? "Loading tours…"
            : loadError
              ? "Unable to load tours"
              : `${total} ${
                  total === 1
                      ? "tour"
                      : "tours"
                } in your catalogue`
        }
        action={
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                load(page)
              }
              disabled={isLoading}
            >
              <RefreshCw
                className={`h-3.5 w-3.5 ${
                  isLoading
                      ? "animate-spin"
                      : ""
                }`}
              />
              Refresh
            </Button>

            <Button
              asChild
              size="sm"
            >
              <Link href="/tours/new">
                <Plus className="h-3.5 w-3.5" />
                New tour
              </Link>
            </Button>
          </div>
        }
      />

      {!isLoading &&
        !loadError &&
        total > 0 && (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard
              label="Total"
              value={total}
              description="Tours in catalogue"
              icon={Map}
              accent
            />

            <StatCard
              label="Active"
              value={pageStats.active}
              description="On this page"
              icon={CheckCircle2}
            />

            <StatCard
              label="Inactive"
              value={pageStats.inactive}
              description="On this page"
              icon={Clock}
            />

          </div>
        )}

      <Card>
        <CardContent className="p-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />

              <Input
                placeholder="Search name, destination or category..."
                value={search}
                onChange={(e) =>
                  setSearch(
                    e.target.value,
                  )
                }
                className="border-none bg-muted/50 pl-9 shadow-none"
              />
            </div>

            <Select
              value={category}
              onValueChange={(value) =>
                setCategory(
                  value as
                    | TourCategory
                    | "ALL",
                )
              }
            >
              <SelectTrigger className="w-full border-none bg-muted/50 shadow-none sm:w-52">
                <SelectValue />
              </SelectTrigger>

              <SelectContent>
                {CATEGORIES.map(
                  (item) => (
                    <SelectItem
                      key={item.value}
                      value={item.value}
                    >
                      {item.label}
                    </SelectItem>
                  ),
                )}
              </SelectContent>
            </Select>

            {search && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() =>
                  setSearch("")
                }
              >
                Clear
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({
            length: 7,
          }).map((_, index) => (
            <Skeleton
              key={index}
              className="h-16 w-full rounded-xl"
            />
          ))}
        </div>
      ) : loadError ? (
        <EmptyState
          icon={AlertTriangle}
          title="Couldn't load tours"
          description={loadError}
          action={
            <Button
              variant="outline"
              size="sm"
              className="mt-4"
              onClick={() =>
                load(page)
              }
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Try again
            </Button>
          }
        />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Map}
          title={
            search
              ? "No matching tours"
              : "No tours found"
          }
          description={
            search
              ? "Try another name, destination or category."
              : "Create your first enquire-button.tsx to start taking bookings."
          }
          action={
            !search ? (
              <Button
                asChild
                size="sm"
                className="mt-4"
              >
                <Link href="/tours/new">
                  <Plus className="h-3.5 w-3.5" />
                  Create first tour
                </Link>
              </Button>
            ) : undefined
          }
        />
      ) : (
        <>
          {/* Desktop table */}
          <div className="hidden overflow-hidden rounded-xl border border-border bg-card shadow-sm lg:block">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Tour</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Price</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>

              <TableBody>
                {filtered.map(
                  (tour) => (
                    <TableRow
                      key={tour.id}
                      className="group cursor-pointer"
                      onClick={() =>
                        openDetail(tour)
                      }
                    >
                      <TableCell>
                        <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
                          <Map className="h-3.5 w-3.5" />
                          {tour.destination}
                        </div>
                      </TableCell>

                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`rounded-full border-none text-[10px] font-medium ${
                            CATEGORY_STYLES[
                                tour.category
                                ] ??
                            "bg-muted text-muted-foreground"
                          }`}
                        >
                          {titleCase(
                            tour.category,
                          )}
                        </Badge>
                      </TableCell>

                      <TableCell className="whitespace-nowrap font-mono text-xs font-medium">
                        {formatCurrency(
                          tour.price,
                          tour.currency,
                        )}
                      </TableCell>

                      <TableCell>
                        <StatusBadge
                          active={
                            tour.active
                          }
                        />
                      </TableCell>

                      <TableCell>
                        <ArrowRight className="h-4 w-4 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                      </TableCell>
                    </TableRow>
                  ),
                )}
              </TableBody>
            </Table>
          </div>

          {/* Mobile cards */}
          <div className="grid gap-3 lg:hidden">
            {filtered.map(
              (tour) => (
                <Card
                  key={tour.id}
                  className="cursor-pointer transition-all hover:border-primary/30"
                  onClick={() =>
                    openDetail(tour)
                  }
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate font-medium">
                          {tour.name}
                        </p>

                        <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                          <Map className="h-3.5 w-3.5" />
                          {tour.destination}
                        </p>
                      </div>

                      <StatusBadge
                        active={
                          tour.active
                        }
                      />
                    </div>

                    <Separator className="my-4" />

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                          Category
                        </p>

                        <Badge
                          variant="outline"
                          className={`mt-1 rounded-full border-none text-[10px] ${
                            CATEGORY_STYLES[
                                tour.category
                                ] ??
                            "bg-muted text-muted-foreground"
                          }`}
                        >
                          {titleCase(
                            tour.category,
                          )}
                        </Badge>
                      </div>

                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                          Duration
                        </p>

                        <p className="mt-1 text-sm">
                          {
                            tour.durationDays
                          }{" "}
                          days
                        </p>
                      </div>

                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                          Price
                        </p>

                        <p className="mt-1 font-mono text-sm font-semibold">
                          {formatCurrency(
                            tour.price,
                            tour.currency,
                          )}
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ),
            )}
          </div>

          {totalPages > 1 && (
            <div className="flex flex-col gap-3 pt-2 sm:flex-row sm:items-center sm:justify-between">
              <span className="text-xs text-muted-foreground">
                Showing{" "}
                <strong className="font-medium text-foreground">
                  {page * PAGE_SIZE +
                    1}
                </strong>
                {" – "}
                <strong className="font-medium text-foreground">
                  {Math.min(
                    (page + 1) *
                      PAGE_SIZE,
                    total,
                  )}
                </strong>
                {" of "}
                {total}
              </span>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    load(page - 1)
                  }
                  disabled={
                    page === 0 ||
                    isLoading
                  }
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  Previous
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    load(page + 1)
                  }
                  disabled={
                    page + 1 >=
                      totalPages ||
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

      {/* Detail sheet */}
      <Sheet
          open={!!selected}
          onOpenChange={(open) => {
            if (!open) closeDetail();
          }}
      >
        <SheetContent
            className="
              w-full overflow-hidden border-l border-white/10
              bg-background/90 p-0 shadow-2xl
              backdrop-blur-2xl
              sm:max-w-lg
              dark:bg-background/80
            "
        >
          {selected && (
              <div className="flex h-full min-h-0 flex-col">
                {/* ─────────────────────────────────────────
            Header / Hero
        ───────────────────────────────────────── */}
                <SheetHeader
                    className="
                      relative shrink-0 overflow-hidden
                      border-b border-border/50
                      px-6 pb-6 pt-7
                      sm:px-7
                    "
                >
                  {/* Ambient glow */}
                  <div
                      aria-hidden
                      className="
                        pointer-events-none absolute
                        -right-24 -top-24
                        h-64 w-64 rounded-full
                        bg-primary/10 blur-3xl
                      "
                  />

                  <div
                      aria-hidden
                      className="
                        pointer-events-none absolute
                        -bottom-16 -left-20
                        h-40 w-40 rounded-full
                        bg-primary/[0.04] blur-3xl
                      "
                  />

                  {/* Header content gets its own safe area.
              This prevents the title/status from visually
              competing with SheetContent's close button. */}
                  <div className="relative pr-12">
                    {/* Eyebrow */}
                    <div className="mb-3 flex items-center gap-2">
                      <span
                          aria-hidden
                          className="
                          inline-flex h-2 w-2 shrink-0 rounded-full
                          bg-emerald-500
                          shadow-[0_0_10px_rgba(16,185,129,0.6)]
                        "
                      />

                      <span
                          className="
                            text-[10px] font-semibold uppercase
                            tracking-[0.18em] text-muted-foreground
                          "
                      >
                        Tour details
                      </span>
                    </div>

                    {/* Title */}
                    <SheetTitle
                        className="
                          max-w-[calc(100%-1rem)]
                          font-display text-2xl font-semibold
                          leading-tight tracking-tight
                          sm:text-[1.65rem]
                        "
                    >
                      {selected.name}
                    </SheetTitle>

                    {/* Destination */}
                    <SheetDescription
                        className="
                          mt-2 flex min-w-0
                          items-center gap-1.5
                          text-xs
                        "
                    >
                      <Map
                          className="
                            h-3.5 w-3.5 shrink-0
                            text-muted-foreground
                          "
                      />

                      <span className="truncate">
                        {selected.destination}
                      </span>
                    </SheetDescription>

                    {/* Status gets its own row */}
                    <div className="mt-4">
                      <StatusBadge active={selected.active} />
                    </div>
                  </div>
                </SheetHeader>

                {/* ─────────────────────────────────────────
                    Content
                ───────────────────────────────────────── */}
                <div className="flex min-h-0 flex-1 flex-col px-6 sm:px-7">
                  <div className="flex-1 space-y-6 overflow-y-auto py-6 pr-1">
                    {/* Price Card */}
                    <motion.div
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.25 }}
                        className="
                          relative overflow-hidden rounded-2xl
                          border border-white/10
                          bg-white/[0.04] p-5
                          shadow-sm
                          backdrop-blur-xl
                          dark:bg-white/[0.03]
                        "
                    >
                      <div
                          aria-hidden
                          className="
                            pointer-events-none absolute
                            -right-10 -top-10
                            h-32 w-32 rounded-full
                            bg-primary/10 blur-2xl
                          "
                      />

                      <div className="relative">
                        <p
                            className="
                              text-[10px] font-semibold uppercase
                              tracking-[0.14em]
                              text-muted-foreground
                            "
                        >
                          Price per person
                        </p>

                        <div className="mt-1 flex items-end gap-2">
                          <p
                              className="
                                font-display text-3xl font-semibold
                                tracking-tight
                              "
                          >
                            {formatCurrency(
                                selected.price,
                                selected.currency,
                            )}
                          </p>

                          <span className="mb-1 text-xs text-muted-foreground">
                            / person
                          </span>
                        </div>
                      </div>
                    </motion.div>

                    {/* Overview */}
                    <section>
                      <div className="mb-3">
                        <p className="text-sm font-semibold">
                          Overview
                        </p>

                        <p className="mt-0.5 text-xs text-muted-foreground">
                          Core operational details for this tour.
                        </p>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        {/* Category */}
                        <div
                            className="
                              rounded-xl border border-border/50
                              bg-muted/20 p-4
                              transition-colors
                              hover:bg-muted/40
                            "
                        >
                          <p
                              className="
                                text-[10px] font-medium uppercase
                                tracking-wide text-muted-foreground
                              "
                          >
                            Category
                          </p>

                          <Badge
                              variant="outline"
                              className={`
                                mt-2 rounded-full border-none
                                text-[10px]
                                ${
                                            CATEGORY_STYLES[selected.category] ??
                                            "bg-muted text-muted-foreground"
                                        }
                              `}
                          >
                            {titleCase(selected.category)}
                          </Badge>
                        </div>

                        {/* Duration */}
                        <div
                            className="
                              rounded-xl border border-border/50
                              bg-muted/20 p-4
                              transition-colors
                              hover:bg-muted/40
                            "
                        >
                          <p
                              className="
                                text-[10px] font-medium uppercase
                                tracking-wide text-muted-foreground
                              "
                          >
                            Duration
                          </p>

                          <div className="mt-2 flex items-center gap-2">
                            <Clock className="h-4 w-4 text-muted-foreground" />

                            <span className="text-sm font-semibold">
                              {selected.durationDays}{" "}
                                      {selected.durationDays === 1
                                          ? "day"
                                          : "days"}
                            </span>
                          </div>
                        </div>
                      </div>
                    </section>

                    {/* Management */}
                    <section>
                      <div className="mb-3">
                        <p className="text-sm font-semibold">
                          Manage tour
                        </p>

                        <p className="mt-0.5 text-xs text-muted-foreground">
                          View details or change its catalogue status.
                        </p>
                      </div>

                      <div className="space-y-2.5">
                        {/* View / Edit */}
                        <Button
                            asChild
                            variant="outline"
                            className="
                              group h-11 w-full justify-between
                              border-border/60
                              bg-background/40
                              backdrop-blur
                              transition-all
                              hover:bg-muted/60
                            "
                        >
                          <Link href={`/tours/${selected.id}`}>
                          <span className="flex items-center gap-2.5">
                            <span
                                className="
                                flex h-7 w-7 items-center
                                justify-center rounded-lg
                                bg-muted
                              "
                            >
                              <Eye className="h-3.5 w-3.5" />
                            </span>

                            <span className="text-sm font-medium">
                              View / edit tour
                            </span>
                          </span>

                            <ArrowRight
                                className="
                                  h-4 w-4 text-muted-foreground
                                  transition-transform
                                  group-hover:translate-x-0.5
                                "
                            />
                          </Link>
                        </Button>

                        {/* Publish */}
                        {!selected.active && (
                            <Button
                                onClick={handlePublish}
                                disabled={isProcessing}
                                className="
                                  h-11 w-full
                                  shadow-lg shadow-primary/10
                                  transition-all
                                  hover:-translate-y-0.5
                                  active:translate-y-0
                                "
                            >
                              <CheckCircle2 className="mr-2 h-4 w-4" />

                              {isProcessing
                                  ? "Publishing…"
                                  : "Publish tour"}
                            </Button>
                        )}
                      </div>
                    </section>

                    {/* Danger Zone */}
                    <section
                        className="
                          rounded-xl
                          border border-destructive/15
                          bg-destructive/[0.025]
                          p-4
                        "
                    >
                      <div className="flex items-start gap-3">
                        <div
                            className="
                              flex h-8 w-8 shrink-0
                              items-center justify-center
                              rounded-lg bg-destructive/10
                            "
                        >
                          <AlertTriangle
                              className="h-4 w-4 text-destructive"
                          />
                        </div>

                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-semibold text-destructive">
                            Danger zone
                          </p>

                          <p className="mt-0.5 text-xs leading-5 text-muted-foreground">
                            Deleting this tour removes it from the
                            catalogue.
                          </p>
                        </div>
                      </div>

                      {confirmingDelete && (
                          <div
                              className="
                                mt-3 rounded-lg
                                border border-destructive/20
                                bg-destructive/5
                                p-3
                              "
                          >
                            <p className="text-xs leading-5 text-muted-foreground">
                              Are you sure you want to delete{" "}
                              <strong className="text-foreground">
                                {selected.name}
                              </strong>
                              ? Click delete again to confirm.
                            </p>
                          </div>
                      )}

                      <Button
                          variant="destructive"
                          onClick={handleDelete}
                          disabled={isProcessing}
                          className="mt-3 h-10 w-full"
                      >
                        <Trash2 className="mr-2 h-4 w-4" />

                        {isProcessing
                            ? "Deleting…"
                            : confirmingDelete
                                ? "Confirm deletion"
                                : "Delete tour"}
                      </Button>
                    </section>

                    {/* Bottom breathing room for mobile */}
                    <div className="h-1" aria-hidden />
                  </div>

                  {/* ─────────────────────────────────────────
                      Sticky Footer
                  ───────────────────────────────────────── */}
                  <SheetFooter
                      className="
                        -mx-6 shrink-0
                        border-t border-border/50
                        bg-background/80
                        px-6 py-4
                        backdrop-blur-xl
                        sm:-mx-7 sm:px-7
                      "
                  >
                    <Button
                        variant="ghost"
                        onClick={closeDetail}
                        className="
                          h-10 w-full
                          rounded-xl
                          sm:w-auto
                        "
                    >
                      Close
                    </Button>
                  </SheetFooter>
                </div>
              </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
