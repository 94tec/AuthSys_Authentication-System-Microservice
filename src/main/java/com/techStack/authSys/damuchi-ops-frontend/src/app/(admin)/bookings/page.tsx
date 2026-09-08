"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  BookOpen, RefreshCw, AlertTriangle, CheckCircle2, XCircle,
  Users, Wallet, Clock, CreditCard,
} from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { bookingApi } from "@/lib/booking-api";
import {
  bookingStatusLabel, formatCurrency, formatDateShort, formatDateTime,
} from "@/lib/utils";
import type { ApiError, Booking, BookingStatus } from "@/types";

const STATUSES: { value: BookingStatus | "ALL"; label: string }[] = [
  { value: "ALL",              label: "All bookings" },
  { value: "PENDING_PAYMENT",  label: "Pending payment" },
  { value: "CONFIRMED",        label: "Confirmed" },
  { value: "COMPLETED",        label: "Completed" },
  { value: "CANCELLED",        label: "Cancelled" },
  { value: "REFUNDED",         label: "Refunded" },
];

// Semantic mapping, same shape as EnquiriesPage's STATUS_BADGE — not
// reusing bookingStatusBadgeClass here since this page now renders shadcn
// <Badge variant> instead of a raw className string. bookingStatusBadgeClass
// is left untouched in lib/utils for whatever else still depends on it
// (e.g. the /staff/bookings/[id] detail page, if it still uses the old
// design system) — not deleting a shared util blind.
const STATUS_BADGE: Record<BookingStatus, "success" | "warning" | "destructive" | "outline" | "secondary"> = {
  PENDING_PAYMENT: "warning",
  CONFIRMED: "success",
  COMPLETED: "outline",
  CANCELLED: "destructive",
  REFUNDED: "secondary",
};

export default function StaffBookingsPage() {
  const searchParams = useSearchParams();
  const initialStatus = (searchParams.get("status") as BookingStatus | null) ?? "ALL";

  const [bookings, setBookings] = useState<Booking[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [status, setStatus] = useState<BookingStatus | "ALL">(initialStatus);
  const [search, setSearch] = useState("");

  // Detail / action panel
  const [selected, setSelected] = useState<Booking | null>(null);
  const [paymentRef, setPaymentRef] = useState("");
  const [cancelReason, setCancelReason] = useState("");
  const [confirmingComplete, setConfirmingComplete] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  const load = useCallback(async () => {
    setIsLoading(true);
    setLoadError(null);
    try {
      const data = await bookingApi.all(status === "ALL" ? undefined : status);
      setBookings(Array.isArray(data) ? data : []);
    } catch (err) {
      const message = (err as ApiError).message || "Couldn't load bookings.";
      setLoadError(message);
      setBookings([]);
      toast.error(message);
    } finally {
      setIsLoading(false);
    }
  }, [status]);

  useEffect(() => { load(); }, [load]);

  const filtered = search.trim()
      ? bookings.filter((b) =>
          b.tourName.toLowerCase().includes(search.toLowerCase()) ||
          b.customerName.toLowerCase().includes(search.toLowerCase()) ||
          b.customerEmail.toLowerCase().includes(search.toLowerCase())
      )
      : bookings;

  const pendingCount = bookings.filter((b) => b.status === "PENDING_PAYMENT").length;
  const confirmedCount = bookings.filter((b) => b.status === "CONFIRMED").length;

  function openDetail(booking: Booking) {
    setSelected(booking);
    setPaymentRef("");
    setCancelReason("");
    setConfirmingComplete(false);
  }

  function closeDetail() {
    setSelected(null);
  }

  async function handleConfirm() {
    if (!selected) return;
    if (!paymentRef.trim()) {
      toast.error("Enter a payment reference first.");
      return;
    }
    setIsProcessing(true);
    try {
      const updated = await bookingApi.confirm(selected.id, paymentRef.trim());
      setBookings((prev) => prev.map((b) => (b.id === updated.id ? updated : b)));
      setSelected(updated);
      toast.success("Booking confirmed.");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't confirm booking.");
    } finally {
      setIsProcessing(false);
    }
  }

  async function handleCancel() {
    if (!selected) return;
    if (!cancelReason.trim()) {
      toast.error("Enter a cancellation reason first.");
      return;
    }
    setIsProcessing(true);
    try {
      const updated = await bookingApi.staffCancel(selected.id, cancelReason.trim());
      setBookings((prev) => prev.map((b) => (b.id === updated.id ? updated : b)));
      setSelected(updated);
      toast.success("Booking cancelled.");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't cancel booking.");
    } finally {
      setIsProcessing(false);
    }
  }

  async function handleComplete() {
    if (!selected) return;
    if (!confirmingComplete) {
      setConfirmingComplete(true);
      return;
    }
    setIsProcessing(true);
    try {
      const updated = await bookingApi.complete(selected.id);
      setBookings((prev) => prev.map((b) => (b.id === updated.id ? updated : b)));
      setSelected(updated);
      setConfirmingComplete(false);
      toast.success("Booking marked as completed.");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't mark booking as completed.");
    } finally {
      setIsProcessing(false);
    }
  }

  return (
      <div className="space-y-7">
        <PageHeader
            eyebrow="Tour Operations"
            title="Bookings"
            subtitle={
              isLoading ? "Loading…"
                  : loadError ? "Unable to load bookings"
                      : `${filtered.length} record${filtered.length !== 1 ? "s" : ""}`
            }
            action={
              <Button variant="outline" size="sm" onClick={load} disabled={isLoading}>
                <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            }
        />

        {!isLoading && !loadError && bookings.length > 0 && (
            <div className="grid grid-cols-2 gap-3 sm:max-w-sm">
              <Card className="border-none bg-amber-500/5 shadow-none">
                <CardContent className="p-4">
                  <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">Pending payment</p>
                  <p className="mt-1 font-display text-2xl font-semibold text-amber-600 dark:text-amber-400">{pendingCount}</p>
                </CardContent>
              </Card>
              <Card className="border-none bg-expedition-forest/5 shadow-none">
                <CardContent className="p-4">
                  <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">Confirmed</p>
                  <p className="mt-1 font-display text-2xl font-semibold">{confirmedCount}</p>
                </CardContent>
              </Card>
            </div>
        )}

        <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-3 sm:flex-row sm:items-center">
          <Input
              placeholder="Search by tour, customer, email…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="border-none bg-muted/50 shadow-none sm:flex-1"
          />
          <Select value={status} onValueChange={(v) => setStatus(v as BookingStatus | "ALL")}>
            <SelectTrigger className="border-none bg-muted/50 shadow-none sm:w-52">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map((s) => (
                  <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-xl" />)}
            </div>
        ) : loadError ? (
            <EmptyState icon={AlertTriangle} title="Couldn't load bookings" description={loadError} />
        ) : filtered.length === 0 ? (
            <EmptyState icon={BookOpen} title="No bookings found" description="Bookings will show up here once customers book a tour." />
        ) : (
            <div className="overflow-hidden rounded-xl border border-border bg-card shadow-sm">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Customer</TableHead>
                    <TableHead>Tour</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead>Travelers</TableHead>
                    <TableHead>Total</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Booked</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((booking) => (
                      <TableRow key={booking.id} className="cursor-pointer" onClick={() => openDetail(booking)}>
                        <TableCell>
                          <p className="font-medium leading-tight">{booking.customerName}</p>
                          <p className="text-xs text-muted-foreground">{booking.customerEmail}</p>
                        </TableCell>
                        <TableCell className="text-sm">
                          <Link
                              href={`/staff/bookings/${booking.id}`}
                              onClick={(e) => e.stopPropagation()}
                              className="font-medium text-accent hover:underline"
                          >
                            {booking.tourName}
                          </Link>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatDateShort(booking.tourDate)}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{booking.travelerCount}</TableCell>
                        <TableCell className="whitespace-nowrap font-mono text-xs">
                          {formatCurrency(booking.totalPrice, booking.currency)}
                        </TableCell>
                        <TableCell>
                          <Badge variant={STATUS_BADGE[booking.status]} className="rounded-full text-[10px] font-medium">
                            {bookingStatusLabel(booking.status)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{formatDateTime(booking.createdDate)}</TableCell>
                      </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
        )}

        {/* Detail / action panel */}
        <Sheet open={!!selected} onOpenChange={(open) => !open && closeDetail()}>
          <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
            {selected && (
                <>
                  <SheetHeader>
                    <SheetTitle className="font-display">{selected.customerName}</SheetTitle>
                    <SheetDescription>{selected.customerEmail}</SheetDescription>
                  </SheetHeader>

                  <div className="space-y-6 py-4">
                    <section className="space-y-2 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Tour</span>
                        <Link
                            href={`/staff/bookings/${selected.id}`}
                            className="font-medium text-accent hover:underline"
                        >
                          {selected.tourName}
                        </Link>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Tour date</span>
                        <span>{formatDateShort(selected.tourDate)}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Travelers</span>
                        <span className="inline-flex items-center gap-1">
                      <Users className="h-3.5 w-3.5" />
                          {selected.travelerCount}
                    </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Total</span>
                        <span className="inline-flex items-center gap-1 font-mono">
                      <Wallet className="h-3.5 w-3.5" />
                          {formatCurrency(selected.totalPrice, selected.currency)}
                    </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Status</span>
                        <Badge variant={STATUS_BADGE[selected.status]} className="rounded-full text-[10px] font-medium">
                          {bookingStatusLabel(selected.status)}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Booked</span>
                        <span className="inline-flex items-center gap-1">
                      <Clock className="h-3.5 w-3.5" />
                          {formatDateTime(selected.createdDate)}
                    </span>
                      </div>
                      {selected.paymentReference && (
                          <div className="flex items-center justify-between">
                            <span className="text-muted-foreground">Payment ref</span>
                            <span className="inline-flex items-center gap-1 font-mono text-xs">
                        <CreditCard className="h-3.5 w-3.5" />
                              {selected.paymentReference}
                      </span>
                          </div>
                      )}
                      {selected.cancellationReason && (
                          <div className="flex items-center justify-between">
                            <span className="text-muted-foreground">Cancellation reason</span>
                            <span className="text-right">{selected.cancellationReason}</span>
                          </div>
                      )}
                    </section>

                    {selected.specialRequests && (
                        <section className="space-y-1">
                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Special requests</p>
                          <p className="text-sm">{selected.specialRequests}</p>
                        </section>
                    )}

                    {(selected.status === "PENDING_PAYMENT" || selected.status === "CONFIRMED") && <Separator />}

                    {selected.status === "PENDING_PAYMENT" && (
                        <section className="space-y-3">
                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Confirm payment</p>
                          <div className="space-y-1.5">
                            <Label>Payment reference</Label>
                            <Input
                                placeholder="e.g. M-Pesa code, receipt number"
                                value={paymentRef}
                                onChange={(e) => setPaymentRef(e.target.value)}
                            />
                          </div>
                          <Button size="sm" onClick={handleConfirm} disabled={isProcessing} className="w-full">
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            {isProcessing ? "Confirming…" : "Confirm booking"}
                          </Button>
                        </section>
                    )}

                    {selected.status === "CONFIRMED" && (
                        <section className="space-y-3">
                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Complete</p>
                          <Button
                              size="sm"
                              variant={confirmingComplete ? "default" : "outline"}
                              onClick={handleComplete}
                              disabled={isProcessing}
                              className="w-full"
                          >
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            {isProcessing
                                ? "Completing…"
                                : confirmingComplete
                                    ? "Click again to confirm"
                                    : "Mark as completed"}
                          </Button>
                        </section>
                    )}

                    {(selected.status === "PENDING_PAYMENT" || selected.status === "CONFIRMED") && (
                        <section className="space-y-3">
                          <p className="text-xs font-semibold uppercase tracking-wide text-destructive">Cancel booking</p>
                          <Textarea
                              rows={2}
                              placeholder="Reason for cancellation"
                              value={cancelReason}
                              onChange={(e) => setCancelReason(e.target.value)}
                          />
                          <Button
                              size="sm"
                              variant="destructive"
                              onClick={handleCancel}
                              disabled={isProcessing}
                              className="w-full"
                          >
                            <XCircle className="h-3.5 w-3.5" />
                            {isProcessing ? "Cancelling…" : "Cancel booking"}
                          </Button>
                        </section>
                    )}
                  </div>

                  <SheetFooter>
                    <Button variant="outline" onClick={closeDetail}>Close</Button>
                  </SheetFooter>
                </>
            )}
          </SheetContent>
        </Sheet>
      </div>
  );
}