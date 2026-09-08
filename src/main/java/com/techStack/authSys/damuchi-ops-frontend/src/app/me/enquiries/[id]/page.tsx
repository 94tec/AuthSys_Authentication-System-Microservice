"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import {
    AlertTriangle, CheckCircle2, Clock, Copy, Download, Landmark, ShieldCheck, Smartphone, XCircle,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import {
    Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";

import { enquiryApi } from "@/lib/enquiry-api";
import { paymentApi } from "@/lib/payment-api";
import { PAYMENT_DETAILS, PAYMENT_TERMS } from "@/lib/payment-details";
import { formatCurrency } from "@/lib/utils";
import type { EnquiryDetailResponse, QuoteResponse } from "@/types/enquiry-types";
import type { PaymentChannel, PaymentSubmissionResponse } from "@/types/payment-types";
import type { ApiError } from "@/types/index-types";

function errMsg(err: unknown, fallback: string) {
    return (err as ApiError)?.message || fallback;
}

function shortDate(iso?: string) {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function isExpired(validUntil: string) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return new Date(validUntil) < today;
}

async function copy(text: string) {
    try {
        await navigator.clipboard.writeText(text);
        toast.success("Copied");
    } catch {
        toast.error("Couldn't copy");
    }
}

function CopyRow({ label, value }: { label: string; value: string }) {
    return (
        <div className="flex items-center justify-between gap-3 text-sm">
            <span className="text-muted-foreground">{label}</span>
            <span className="inline-flex items-center gap-2 font-mono font-medium">
                {value}
                <button type="button" onClick={() => copy(value)} className="text-muted-foreground hover:text-foreground" aria-label={`Copy ${label}`}>
                    <Copy className="h-3.5 w-3.5" />
                </button>
            </span>
        </div>
    );
}

function SubmissionBadge({ status }: { status: PaymentSubmissionResponse["status"] }) {
    const map = {
        PENDING_VERIFICATION: { label: "Awaiting verification", cls: "border-amber-200 bg-amber-50 text-amber-700", icon: Clock },
        VERIFIED: { label: "Verified", cls: "border-emerald-200 bg-emerald-50 text-emerald-700", icon: CheckCircle2 },
        REJECTED: { label: "Rejected", cls: "border-red-200 bg-red-50 text-red-700", icon: XCircle },
    } as const;
    const { label, cls, icon: Icon } = map[status];
    return (
        <Badge variant="outline" className={`rounded-full text-[10px] ${cls}`}>
            <Icon className="mr-1 h-3 w-3" />
            {label}
        </Badge>
    );
}

/* ───────────── Payment instructions ───────────── */

function PaymentInstructions({ quote }: { quote: QuoteResponse }) {
    return (
        <div className="space-y-4 rounded-2xl border border-accent/30 bg-accent/[0.04] p-5">
            <div>
                <p className="text-sm font-semibold">How to pay</p>
                <p className="mt-1 text-xs text-muted-foreground">
                    Pay through either channel, then submit your transaction reference below so we can confirm your booking.
                </p>
            </div>

            <div className="space-y-2 rounded-xl bg-background p-4">
                <p className="inline-flex items-center gap-1.5 text-xs font-semibold text-primary">
                    <Smartphone className="h-3.5 w-3.5" /> M-Pesa Paybill
                </p>
                <CopyRow label="Business number" value={PAYMENT_DETAILS.mpesa.paybill} />
                <CopyRow label="Account number" value={PAYMENT_DETAILS.mpesa.account} />
            </div>

            <div className="space-y-2 rounded-xl bg-background p-4">
                <p className="inline-flex items-center gap-1.5 text-xs font-semibold text-primary">
                    <Landmark className="h-3.5 w-3.5" /> Bank transfer
                </p>
                <CopyRow label="Bank" value={PAYMENT_DETAILS.bank.name} />
                <CopyRow label="Account name" value={PAYMENT_DETAILS.bank.accountName} />
                <CopyRow label="Account number" value={PAYMENT_DETAILS.bank.accountNumber} />
                <CopyRow label="Branch" value={PAYMENT_DETAILS.bank.branch} />
                <CopyRow label="SWIFT/BIC" value={PAYMENT_DETAILS.bank.swift} />
            </div>

            <p className="text-[11px] leading-5 text-muted-foreground">
                Quote reference: <span className="font-mono">{quote.id}</span>. For bank transfers, put it in the payment
                description. For M-Pesa, keep the confirmation SMS. You'll need its transaction code.
            </p>
        </div>
    );
}

/* ───────────── Payment submission form ───────────── */

function PaymentSubmissionForm({
                                   enquiryId, quote, onSubmitted,
                               }: {
    enquiryId: string;
    quote: QuoteResponse;
    onSubmitted: () => void;
}) {
    const deposit = Math.round(quote.totalPrice * (PAYMENT_DETAILS.depositPercent / 100) * 100) / 100;

    const [channel, setChannel] = useState<PaymentChannel>("MPESA");
    const [referenceCode, setReferenceCode] = useState("");
    const [amount, setAmount] = useState(String(deposit));
    const [payerName, setPayerName] = useState("");
    const [isSubmitting, setIsSubmitting] = useState(false);

    async function handleSubmit() {
        const ref = referenceCode.trim().toUpperCase();
        const amt = Number(amount);

        if (!/^[A-Z0-9-]{6,40}$/.test(ref)) {
            toast.error("Enter the transaction reference exactly as shown in your M-Pesa SMS or bank receipt.");
            return;
        }
        if (!(amt > 0)) {
            toast.error("Enter the amount you paid.");
            return;
        }
        if (amt > quote.totalPrice) {
            toast.error("The amount can't be more than the quote total.");
            return;
        }
        if (!payerName.trim()) {
            toast.error("Enter the name or phone number the payment was sent from.");
            return;
        }

        setIsSubmitting(true);
        try {
            await paymentApi.submitPayment(enquiryId, quote.id, {
                channel,
                referenceCode: ref,
                amountPaid: amt,
                payerName: payerName.trim(),
            });
            toast.success("Payment reference submitted. We'll confirm it shortly.");
            onSubmitted();
        } catch (err) {
            toast.error(errMsg(err, "Couldn't submit your payment reference."));
        } finally {
            setIsSubmitting(false);
        }
    }

    return (
        <div className="space-y-4 rounded-2xl border border-border/70 bg-card p-5">
            <div>
                <p className="text-sm font-semibold">I've made a payment</p>
                <p className="mt-1 text-xs text-muted-foreground">Submit the details of the payment you just sent.</p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                    <Label className="text-xs">Paid via</Label>
                    <Select value={channel} onValueChange={(v) => setChannel(v as PaymentChannel)}>
                        <SelectTrigger className="rounded-xl"><SelectValue /></SelectTrigger>
                        <SelectContent>
                            <SelectItem value="MPESA">M-Pesa Paybill</SelectItem>
                            <SelectItem value="BANK_TRANSFER">Bank transfer</SelectItem>
                        </SelectContent>
                    </Select>
                </div>

                <div className="space-y-1.5">
                    <Label className="text-xs">Transaction reference</Label>
                    <Input
                        value={referenceCode}
                        onChange={(e) => setReferenceCode(e.target.value.toUpperCase())}
                        placeholder={channel === "MPESA" ? "e.g. SGH7K2L9XQ" : "Bank reference"}
                        autoComplete="off"
                        className="rounded-xl font-mono"
                    />
                </div>

                <div className="space-y-1.5">
                    <Label className="text-xs">Amount paid ({quote.currency})</Label>
                    <Input type="number" min={0} value={amount} onChange={(e) => setAmount(e.target.value)} className="rounded-xl" />
                    <div className="flex gap-3 text-[11px]">
                        <button type="button" className="font-medium text-primary hover:underline" onClick={() => setAmount(String(deposit))}>
                            Deposit ({PAYMENT_DETAILS.depositPercent}%)
                        </button>
                        <button type="button" className="font-medium text-primary hover:underline" onClick={() => setAmount(String(quote.totalPrice))}>
                            Full amount
                        </button>
                    </div>
                </div>

                <div className="space-y-1.5">
                    <Label className="text-xs">Name or phone number used to pay</Label>
                    <Input
                        value={payerName}
                        onChange={(e) => setPayerName(e.target.value)}
                        placeholder="e.g. 07XX XXX XXX or account holder name"
                        className="rounded-xl"
                    />
                </div>
            </div>

            <Button className="w-full rounded-xl" onClick={handleSubmit} disabled={isSubmitting}>
                {isSubmitting ? "Submitting…" : "Submit payment reference"}
            </Button>
        </div>
    );
}

/* ───────────── Quote card with accept flow ───────────── */

function QuoteCard({
                       quote, onDownload, onAccept, isAccepting,
                   }: {
    quote: QuoteResponse;
    onDownload: () => void;
    onAccept: () => void;
    isAccepting: boolean;
}) {
    const [agreed, setAgreed] = useState(false);
    const [reviewing, setReviewing] = useState(false);
    const expired = isExpired(quote.validUntil);

    return (
        <Card>
            <CardContent className="space-y-4 p-5">
                <div className="flex items-start justify-between gap-3">
                    <div>
                        <p className="font-display text-2xl font-semibold">{formatCurrency(quote.totalPrice, quote.currency)}</p>
                        <p className="mt-1 text-xs text-muted-foreground">
                            {quote.adultCount} adult{quote.adultCount !== 1 ? "s" : ""} × {formatCurrency(quote.pricePerAdult, quote.currency)}
                            {quote.childCount > 0 && quote.pricePerChild != null
                                ? ` + ${quote.childCount} child${quote.childCount !== 1 ? "ren" : ""} × ${formatCurrency(quote.pricePerChild, quote.currency)}`
                                : ""}
                        </p>
                    </div>
                    <Badge variant="outline" className="rounded-full text-[10px]">
                        {expired && quote.status === "SENT" ? "EXPIRED" : quote.status}
                    </Badge>
                </div>

                <p className="text-xs text-muted-foreground">
                    Valid until <span className="font-medium text-foreground">{shortDate(quote.validUntil)}</span>
                </p>
                {quote.inclusionsNote && (
                    <p className="whitespace-pre-wrap rounded-xl bg-muted/40 p-3 text-xs leading-5 text-muted-foreground">{quote.inclusionsNote}</p>
                )}

                <div className="flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" className="rounded-xl" onClick={onDownload}>
                        <Download className="mr-1.5 h-3.5 w-3.5" />
                        Download quote (PDF)
                    </Button>
                    {quote.status === "SENT" && !expired && !reviewing && (
                        <Button size="sm" className="rounded-xl" onClick={() => setReviewing(true)}>
                            Review terms & accept
                        </Button>
                    )}
                </div>

                {quote.status === "SENT" && expired && (
                    <p className="text-xs text-destructive">This quote has expired. Please contact us for an updated quote.</p>
                )}

                {quote.status === "SENT" && !expired && reviewing && (
                    <div className="space-y-3 rounded-xl border border-border/70 p-4">
                        <p className="inline-flex items-center gap-1.5 text-xs font-semibold">
                            <ShieldCheck className="h-3.5 w-3.5" /> Payment terms
                        </p>
                        <ul className="list-disc space-y-1 pl-4 text-xs leading-5 text-muted-foreground">
                            {PAYMENT_TERMS.map((term) => <li key={term}>{term}</li>)}
                        </ul>
                        <label className="flex items-start gap-2 text-xs">
                            <input
                                type="checkbox"
                                checked={agreed}
                                onChange={(e) => setAgreed(e.target.checked)}
                                className="mt-0.5 h-4 w-4"
                            />
                            <span>I have read and agree to the payment terms above.</span>
                        </label>
                        <Button className="w-full rounded-xl" onClick={onAccept} disabled={!agreed || isAccepting}>
                            {isAccepting ? "Accepting…" : "Accept quote"}
                        </Button>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}

/* ───────────── Page ───────────── */

export default function MyEnquiryPage() {
    const { id } = useParams<{ id: string }>();

    const [detail, setDetail] = useState<EnquiryDetailResponse | null>(null);
    const [submissions, setSubmissions] = useState<PaymentSubmissionResponse[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [acceptingId, setAcceptingId] = useState<string | null>(null);

    const load = useCallback(async () => {
        try {
            setDetail(await enquiryApi.myEnquiryDetail(id));
            setError(null);
        } catch (err) {
            setError(errMsg(err, "Couldn't load your enquiry."));
            setIsLoading(false);
            return;
        }
        try {
            setSubmissions(await paymentApi.listMine(id));
        } catch (err) {
            toast.error(errMsg(err, "Couldn't load your payment history."));
        }
        setIsLoading(false);
    }, [id]);

    useEffect(() => { load(); }, [load]);

    // Customers never see draft quotes.
    const quotes = useMemo(
        () => (detail?.quotes ?? []).filter((q) => q.status !== "DRAFT"),
        [detail],
    );
    const acceptedQuote = quotes.find((q) => q.status === "ACCEPTED");
    const quoteSubmissions = submissions.filter((s) => s.quoteId === acceptedQuote?.id);
    const hasPending = quoteSubmissions.some((s) => s.status === "PENDING_VERIFICATION");
    const hasVerified = quoteSubmissions.some((s) => s.status === "VERIFIED");

    async function handleDownload(quoteId: string) {
        try {
            const blob = await enquiryApi.downloadQuotePdf(id, quoteId, false);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `damuchi-quote-${quoteId.slice(0, 8)}.pdf`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (err) {
            toast.error(errMsg(err, "Couldn't download the quote."));
        }
    }

    async function handleAccept(quoteId: string) {
        setAcceptingId(quoteId);
        try {
            await enquiryApi.acceptQuote(id, quoteId, { termsAccepted: true });
            toast.success("Quote accepted. Follow the payment steps below.");
            await load();
        } catch (err) {
            toast.error(errMsg(err, "Couldn't accept the quote."));
        } finally {
            setAcceptingId(null);
        }
    }

    if (isLoading) {
        return (
            <div className="mx-auto max-w-3xl space-y-4 p-6">
                <Skeleton className="h-10 w-2/3" />
                <Skeleton className="h-40 w-full rounded-2xl" />
                <Skeleton className="h-64 w-full rounded-2xl" />
            </div>
        );
    }

    if (error || !detail) {
        return (
            <div className="mx-auto max-w-3xl p-6">
                <EmptyState icon={AlertTriangle} title="Couldn't load your enquiry" description={error ?? "Please try again."} />
            </div>
        );
    }

    return (
        <div className="mx-auto max-w-3xl space-y-6 p-6 pb-16">
            <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Your enquiry</p>
                <h1 className="mt-1 font-display text-2xl font-semibold tracking-tight">{detail.tourName}</h1>
            </div>

            {detail.bookingReference && (
                <div className="space-y-1 rounded-2xl border border-emerald-200 bg-emerald-50 p-5">
                    <p className="inline-flex items-center gap-2 text-sm font-semibold text-emerald-800">
                        <CheckCircle2 className="h-4 w-4" /> Booking confirmed
                    </p>
                    <p className="text-sm text-emerald-900">
                        Reference <span className="font-mono font-semibold">{detail.bookingReference}</span>
                        {detail.travelStartDate ? ` · ${shortDate(detail.travelStartDate)} → ${shortDate(detail.travelEndDate)}` : ""}
                    </p>
                    <p className="text-xs text-emerald-800">
                        We've emailed your itinerary and pickup details. Any remaining balance is due 14 days before travel.
                    </p>
                </div>
            )}

            <section className="space-y-3">
                <h2 className="text-sm font-semibold">Quotes</h2>
                {quotes.length === 0 ? (
                    <EmptyState icon={Clock} title="No quote yet" description="We'll email you as soon as your quote is ready." />
                ) : (
                    quotes.map((q) => (
                        <QuoteCard
                            key={q.id}
                            quote={q}
                            onDownload={() => handleDownload(q.id)}
                            onAccept={() => handleAccept(q.id)}
                            isAccepting={acceptingId === q.id}
                        />
                    ))
                )}
            </section>

            {acceptedQuote && !detail.bookingReference && (
                <section className="space-y-4">
                    <h2 className="text-sm font-semibold">Payment</h2>

                    {hasVerified ? (
                        <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800">
                            Your payment is verified. We're preparing your booking and will email you the details.
                        </div>
                    ) : hasPending ? (
                        <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
                            We've received your payment reference and are checking it against our records. We'll email you once it's confirmed.
                        </div>
                    ) : (
                        <>
                            <PaymentInstructions quote={acceptedQuote} />
                            <PaymentSubmissionForm enquiryId={id} quote={acceptedQuote} onSubmitted={load} />
                        </>
                    )}

                    {quoteSubmissions.length > 0 && (
                        <div className="space-y-2">
                            <p className="text-xs font-semibold text-muted-foreground">Your payment submissions</p>
                            {quoteSubmissions.map((s) => (
                                <Card key={s.id}>
                                    <CardContent className="space-y-1 p-4">
                                        <div className="flex items-center justify-between gap-3">
                                            <p className="font-mono text-sm font-medium">{s.referenceCode}</p>
                                            <SubmissionBadge status={s.status} />
                                        </div>
                                        <p className="text-xs text-muted-foreground">
                                            {formatCurrency(s.amountPaid, s.currency)} · {s.channel === "MPESA" ? "M-Pesa" : "Bank transfer"} · {shortDate(s.createdDate)}
                                        </p>
                                        {s.status === "REJECTED" && s.rejectionReason && (
                                            <p className="rounded-lg bg-red-50 p-2 text-xs text-red-700">{s.rejectionReason}</p>
                                        )}
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    )}
                </section>
            )}
        </div>
    );
}