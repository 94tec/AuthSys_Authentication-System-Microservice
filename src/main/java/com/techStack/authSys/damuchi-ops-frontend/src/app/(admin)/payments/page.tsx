"use client";

import { useCallback, useEffect, useState } from "react";
import {
    AlertTriangle, CheckCircle2, Clock, Copy, Landmark, PlaneTakeoff,
    RefreshCw, ShieldCheck, Smartphone, Users, XCircle,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import {
    Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import {
    AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";

import { paymentApi } from "@/lib/payment-api";
import { PAYMENT_DETAILS } from "@/lib/payment-details";
import { formatCurrency } from "@/lib/utils";
import type { PaymentSubmissionResponse } from "@/types/payment-types";
import type { ApiError } from "@/types/index-types";

import { CreateBookingForm } from "./create-booking-form";

type View = "pending" | "awaiting";
type Mode = "review" | "reject" | "booking";

const CHANNEL_META = {
    MPESA: { label: "M-Pesa", icon: Smartphone },
    BANK_TRANSFER: { label: "Bank transfer", icon: Landmark },
} as const;

function errMsg(err: unknown, fallback: string) {
    return (err as ApiError)?.message || fallback;
}

function formatDateTime(iso?: string) {
    if (!iso) return "—";
    return new Date(iso).toLocaleString(undefined, {
        day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
    });
}

async function copy(text: string) {
    try {
        await navigator.clipboard.writeText(text);
        toast.success("Copied");
    } catch {
        toast.error("Couldn't copy");
    }
}

/** Compare what the customer says they paid against the quote and deposit policy. */
function assessAmount(s: PaymentSubmissionResponse) {
    const pct = s.quoteTotal > 0 ? (s.amountPaid / s.quoteTotal) * 100 : 0;
    if (s.amountPaid > s.quoteTotal) return { label: "Exceeds quote total", tone: "bad" as const };
    if (pct >= 99.99) return { label: "Full payment", tone: "ok" as const };
    if (pct >= PAYMENT_DETAILS.depositPercent) return { label: `Deposit met (${pct.toFixed(0)}%)`, tone: "ok" as const };
    return { label: `Below ${PAYMENT_DETAILS.depositPercent}% deposit (${pct.toFixed(0)}%)`, tone: "bad" as const };
}

function AmountBadge({ s }: { s: PaymentSubmissionResponse }) {
    const a = assessAmount(s);
    return (
        <Badge
            variant="outline"
            className={`rounded-full text-[10px] ${
                a.tone === "ok"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                    : "border-red-200 bg-red-50 text-red-700"
            }`}
        >
            {a.label}
        </Badge>
    );
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
    return (
        <div>
            <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
            <div className="mt-1 text-sm font-medium">{children}</div>
        </div>
    );
}

export default function AdminPaymentsPage() {
    const [view, setView] = useState<View>("pending");
    const [pending, setPending] = useState<PaymentSubmissionResponse[]>([]);
    const [awaiting, setAwaiting] = useState<PaymentSubmissionResponse[]>([]);
    const [pendingTotal, setPendingTotal] = useState(0);
    const [awaitingTotal, setAwaitingTotal] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [isRefreshing, setIsRefreshing] = useState(false);
    const [loadError, setLoadError] = useState<string | null>(null);

    const [selected, setSelected] = useState<PaymentSubmissionResponse | null>(null);
    const [mode, setMode] = useState<Mode>("review");
    const [confirmVerify, setConfirmVerify] = useState(false);
    const [rejectReason, setRejectReason] = useState("");
    const [isProcessing, setIsProcessing] = useState(false);

    const load = useCallback(async (silent = false) => {
        if (silent) setIsRefreshing(true);
        else setIsLoading(true);
        setLoadError(null);

        try {
            const [p, a] = await Promise.all([
                paymentApi.adminList("pending"),
                paymentApi.adminList("awaiting-booking"),
            ]);
            setPending(p.content ?? []);
            setPendingTotal(p.totalElements ?? 0);
            setAwaiting(a.content ?? []);
            setAwaitingTotal(a.totalElements ?? 0);
        } catch (err) {
            const message = errMsg(err, "Couldn't load payments.");
            setLoadError(message);
            toast.error(message);
        } finally {
            setIsLoading(false);
            setIsRefreshing(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);

    const rows = view === "pending" ? pending : awaiting;

    function openSubmission(s: PaymentSubmissionResponse) {
        setSelected(s);
        setMode("review");
        setRejectReason("");
    }

    function closeSheet() {
        setSelected(null);
        setMode("review");
        setRejectReason("");
        setConfirmVerify(false);
    }

    async function handleVerify() {
        if (!selected) return;
        setIsProcessing(true);
        try {
            const updated = await paymentApi.adminVerify(selected.id);
            if (updated.isBalancePayment) {
                toast.success("Balance payment verified and applied to the booking.");
                closeSheet();
            } else {
                toast.success("Payment verified. Now create the booking.");
                setSelected(updated);
                setMode("booking");
            }
            load(true);
        } catch (err) {
            toast.error(errMsg(err, "Couldn't verify payment."));
        } finally {
            setIsProcessing(false);
        }
    }

    async function handleReject() {
        if (!selected) return;
        const reason = rejectReason.trim();
        if (reason.length < 5) {
            toast.error("Give the customer a clear reason (at least 5 characters).");
            return;
        }
        setIsProcessing(true);
        try {
            await paymentApi.adminReject(selected.id, reason);
            toast.success("Claim rejected. The customer will see your reason on their dashboard.");
            closeSheet();
            load(true);
        } catch (err) {
            toast.error(errMsg(err, "Couldn't reject payment."));
        } finally {
            setIsProcessing(false);
        }
    }

    const tabs: { key: View; label: string; count: number; icon: React.ElementType }[] = [
        { key: "pending", label: "Pending verification", count: pendingTotal, icon: Clock },
        { key: "awaiting", label: "Verified, awaiting booking", count: awaitingTotal, icon: PlaneTakeoff },
    ];

    return (
        <div className="space-y-7 pb-10">
            <PageHeader
                eyebrow="Tour Operations"
                title="Payments"
                subtitle="Verify customer payment claims, then create their booking."
                action={
                    <Button variant="outline" size="sm" onClick={() => load(true)} disabled={isLoading || isRefreshing}>
                        <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
                        Refresh
                    </Button>
                }
            />

            <div className="flex flex-wrap gap-2">
                {tabs.map(({ key, label, count, icon: Icon }) => (
                    <button
                        key={key}
                        type="button"
                        onClick={() => setView(key)}
                        className={`inline-flex items-center gap-1.5 rounded-full border px-3.5 py-2 text-xs font-medium transition-colors ${
                            view === key
                                ? "border-primary/30 bg-primary/10 text-primary"
                                : "border-border bg-background text-muted-foreground hover:bg-muted"
                        }`}
                    >
                        <Icon className="h-3.5 w-3.5" />
                        {label}
                        <span className="ml-1 rounded-full bg-muted px-1.5 text-[10px] font-semibold">{count}</span>
                    </button>
                ))}
            </div>

            {isLoading ? (
                <div className="space-y-2">
                    {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20 w-full rounded-xl" />)}
                </div>
            ) : loadError ? (
                <EmptyState icon={AlertTriangle} title="Couldn't load payments" description={loadError} />
            ) : rows.length === 0 ? (
                <EmptyState
                    icon={view === "pending" ? Clock : PlaneTakeoff}
                    title={view === "pending" ? "No payments waiting" : "No bookings waiting"}
                    description={
                        view === "pending"
                            ? "New customer payment claims will appear here."
                            : "Verified payments that still need a booking will appear here."
                    }
                />
            ) : (
                <div className="space-y-2">
                    {rows.map((s) => {
                        const Channel = CHANNEL_META[s.channel].icon;
                        return (
                            <Card
                                key={s.id}
                                className="cursor-pointer transition-colors hover:border-primary/30"
                                onClick={() => openSubmission(s)}
                            >
                                <CardContent className="flex flex-wrap items-center gap-4 p-4">
                                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-muted text-muted-foreground">
                                        <Channel className="h-4 w-4" />
                                    </div>
                                    <div className="min-w-0 flex-1">
                                        <p className="truncate font-medium">{s.customerName}</p>
                                        <p className="truncate text-xs text-muted-foreground">
                                            {s.tourName} · {CHANNEL_META[s.channel].label} · {formatDateTime(s.createdDate)}
                                        </p>
                                    </div>
                                    <div className="text-right">
                                        <p className="font-mono text-sm font-semibold">{formatCurrency(s.amountPaid, s.currency)}</p>
                                        <div className="mt-1"><AmountBadge s={s} /></div>
                                    </div>
                                </CardContent>
                            </Card>
                        );
                    })}
                </div>
            )}

            <Sheet open={!!selected} onOpenChange={(open) => !open && closeSheet()}>
                <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
                    {selected && (
                        <>
                            <SheetHeader>
                                <SheetTitle className="font-display text-xl">{selected.customerName}</SheetTitle>
                                <SheetDescription>{selected.tourName}</SheetDescription>
                            </SheetHeader>

                            <div className="space-y-6 py-6">
                                {mode === "booking" ? (
                                    <>
                                        <div className="flex items-start gap-2 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-800">
                                            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
                                            <p>
                                                Payment of {formatCurrency(selected.amountPaid, selected.currency)} verified.
                                                Complete the booking below. The customer is emailed their itinerary and pickup details automatically.
                                            </p>
                                        </div>
                                        <CreateBookingForm
                                            key={selected.id}
                                            submission={selected}
                                            onCancel={closeSheet}
                                            onCreated={(result) => {
                                                toast.success(`Booking ${result.bookingReference} created`);
                                                closeSheet();
                                                load(true);
                                            }}
                                        />
                                    </>
                                ) : (
                                    <>
                                        <div className="grid grid-cols-2 gap-4">
                                            <Detail label="Channel">{CHANNEL_META[selected.channel].label}</Detail>
                                            <Detail label="Submitted">{formatDateTime(selected.createdDate)}</Detail>
                                            <Detail label="Transaction reference">
                                                <span className="inline-flex items-center gap-1.5 font-mono">
                                                    {selected.referenceCode}
                                                    <button
                                                        type="button"
                                                        onClick={() => copy(selected.referenceCode)}
                                                        className="text-muted-foreground hover:text-foreground"
                                                        aria-label="Copy reference"
                                                    >
                                                        <Copy className="h-3.5 w-3.5" />
                                                    </button>
                                                </span>
                                            </Detail>
                                            <Detail label="Payer name / phone">{selected.payerName || "—"}</Detail>
                                            <Detail label="Amount claimed">
                                                <span className="font-mono">{formatCurrency(selected.amountPaid, selected.currency)}</span>
                                            </Detail>
                                            <Detail label="Quote total">
                                                <span className="font-mono">{formatCurrency(selected.quoteTotal, selected.currency)}</span>
                                            </Detail>
                                            <Detail label="Party">
                                                <span className="inline-flex items-center gap-1.5">
                                                    <Users className="h-3.5 w-3.5 text-muted-foreground" />
                                                    {selected.adultCount} adult{selected.adultCount !== 1 ? "s" : ""}
                                                    {selected.childCount > 0 ? ` · ${selected.childCount} child${selected.childCount !== 1 ? "ren" : ""}` : ""}
                                                </span>
                                            </Detail>
                                            <Detail label="Amount check"><AmountBadge s={selected} /></Detail>
                                            {selected.isBalancePayment && (
                                                <Badge variant="outline" className="rounded-full text-[10px] border-violet-200 bg-violet-50 text-violet-700">
                                                    Balance payment
                                                </Badge>
                                            )}
                                        </div>

                                        <Separator />

                                        {selected.status === "PENDING_VERIFICATION" && mode === "review" && (
                                            <div className="space-y-3">
                                                <div className="flex items-start gap-2 rounded-xl bg-muted/50 p-3 text-xs leading-5 text-muted-foreground">
                                                    <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
                                                    <p>
                                                        A customer-typed reference is only a claim. Before verifying, find a payment with this
                                                        exact reference and amount in your M-Pesa Business statement (Paybill {PAYMENT_DETAILS.mpesa.paybill})
                                                        or your KCB statement.
                                                    </p>
                                                </div>
                                                <Button className="w-full" onClick={() => setConfirmVerify(true)} disabled={isProcessing}>
                                                    <CheckCircle2 className="h-4 w-4" />
                                                    Verify payment
                                                </Button>
                                                <Button
                                                    variant="outline"
                                                    className="w-full text-destructive"
                                                    onClick={() => setMode("reject")}
                                                    disabled={isProcessing}
                                                >
                                                    <XCircle className="h-4 w-4" />
                                                    Reject claim
                                                </Button>
                                            </div>
                                        )}

                                        {selected.status === "PENDING_VERIFICATION" && mode === "reject" && (
                                            <div className="space-y-3">
                                                <div className="space-y-1.5">
                                                    <Label className="text-xs">Reason for rejection</Label>
                                                    <Textarea
                                                        rows={3}
                                                        value={rejectReason}
                                                        onChange={(e) => setRejectReason(e.target.value)}
                                                        placeholder="e.g. We couldn't find this reference in our statement. Please re-check the code."
                                                        className="resize-none rounded-xl"
                                                    />
                                                    <p className="text-[11px] text-muted-foreground">
                                                        The customer sees this reason on their dashboard, so keep it clear and polite.
                                                    </p>
                                                </div>
                                                <div className="grid grid-cols-2 gap-2">
                                                    <Button variant="outline" onClick={() => setMode("review")} disabled={isProcessing}>
                                                        Back
                                                    </Button>
                                                    <Button variant="destructive" onClick={handleReject} disabled={isProcessing}>
                                                        {isProcessing ? "Rejecting…" : "Confirm rejection"}
                                                    </Button>
                                                </div>
                                            </div>
                                        )}

                                        {selected.status === "VERIFIED" && !selected.bookingReference && (
                                            <Button className="w-full" onClick={() => setMode("booking")}>
                                                <PlaneTakeoff className="h-4 w-4" />
                                                Create booking
                                            </Button>
                                        )}
                                    </>
                                )}
                            </div>
                        </>
                    )}
                </SheetContent>
            </Sheet>

            <AlertDialog open={confirmVerify} onOpenChange={setConfirmVerify}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>Confirm the money is in your account</AlertDialogTitle>
                        <AlertDialogDescription>
                            You are confirming that reference{" "}
                            <span className="font-mono font-semibold text-foreground">{selected?.referenceCode}</span> for{" "}
                            <span className="font-semibold text-foreground">
                                {selected ? formatCurrency(selected.amountPaid, selected.currency) : ""}
                            </span>{" "}
                            appears in your statement. This is recorded against your account.
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>Not yet</AlertDialogCancel>
                        <AlertDialogAction onClick={handleVerify}>Yes, payment received</AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </div>
    );
}