"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
    AlertTriangle,
    ArrowLeft,
    CalendarDays,
    Check,
    CheckCircle2,
    Clock, Download,
    Inbox,
    Mail,
    MapPin,
    MessageCircle,
    RefreshCw,
    Send,
    Sparkles,
    Users,
    Wallet,
    XCircle,
} from "lucide-react";

import { toast } from "sonner";

import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";

import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";

import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog";

import { enquiryApi } from "@/lib/enquiry-api";

import type {
    EnquiryDetailResponse,
    EnquirySummaryResponse,
    QuoteResponse,
    TourEnquiryStatus,
} from "@/types/enquiry-types";

import type { ApiError } from "@/types/index-types";

/* ============================================================
   CONSTANTS
============================================================ */

const PAGE_SIZE = 12;

const FILTERABLE_STATUSES: TourEnquiryStatus[] = [
    "NEW", "CONTACTED", "QUOTED", "CONVERTED", "COMPLETED", "LOST",
];

const STATUS_COPY: Record<TourEnquiryStatus, { label: string; blurb: string }> = {
    NEW: { label: "Sent", blurb: "We've received your enquiry and will be in touch shortly." },
    CONTACTED: { label: "In conversation", blurb: "A safari specialist is working on your trip." },
    QUOTED: { label: "Quote ready", blurb: "Review your quote below and accept when you're ready." },
    CONVERTED: { label: "Booked", blurb: "Your trip is confirmed — we can't wait to host you." },
    COMPLETED: { label: "Completed", blurb: "We hope you had an unforgettable journey with us." },
    LOST: { label: "Closed", blurb: "This enquiry is no longer active." },
    ARCHIVED: { label: "Archived", blurb: "This enquiry has been archived." },
};

const STATUS_STYLES: Record<TourEnquiryStatus, string> = {
    NEW: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-400",
    CONTACTED: "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-400",
    QUOTED: "border-coral/30 bg-coral/10 text-coral",
    CONVERTED: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-400",
    COMPLETED: "border-teal-200 bg-teal-50 text-teal-700 dark:border-teal-900 dark:bg-teal-950/30 dark:text-teal-400",
    LOST: "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-400",
    ARCHIVED: "border-muted-foreground/20 bg-muted text-muted-foreground",
};

const STATUS_ICONS: Record<TourEnquiryStatus, React.ElementType> = {
    NEW: Inbox,
    CONTACTED: Clock,
    QUOTED: Send,
    CONVERTED: Sparkles,
    COMPLETED: CheckCircle2,
    LOST: XCircle,
    ARCHIVED: XCircle,
};

/* ============================================================
   HELPERS
============================================================ */
async function handleDownloadQuotePdf(
    enquiryId: string,
    quoteId: string
) {
    try {
        const blob = await enquiryApi.downloadQuotePdf(
            enquiryId,
            quoteId,
            true
        );

        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = url;
        a.download = `quote-${quoteId}.pdf`;

        document.body.appendChild(a);
        a.click();
        a.remove();

        URL.revokeObjectURL(url);

        toast.success("Quote PDF downloaded.");
    } catch (err) {
        toast.error(
            getApiErrorMessage(
                err,
                "Couldn't download quote PDF."
            )
        );
    }
}

function formatDate(iso?: string) {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function getApiErrorMessage(err: unknown, fallback: string) {
    return (err as ApiError)?.message || fallback;
}

function generateBookingReference() {
    const stamp = Date.now().toString(36).toUpperCase().slice(-6);
    return `DMC-${stamp}`;
}

/* ============================================================
   PAGE SHELL — matches CategoryLandingPage's Navbar/main/Footer frame
============================================================ */

function PageShell({ children }: { children: React.ReactNode }) {
    return (
        <div className="flex min-h-screen flex-col bg-background">
            <Navbar />
            <main className="flex-1">
                <div className="container py-10 sm:py-14">{children}</div>
            </main>

        </div>
    );
}

/* ============================================================
   STATUS BADGE
============================================================ */

function StatusBadge({ status }: { status: TourEnquiryStatus }) {
    const Icon = STATUS_ICONS[status];
    return (
        <Badge variant="outline" className={`rounded-full px-2.5 py-1 text-[10px] font-semibold ${STATUS_STYLES[status]}`}>
            <Icon className="mr-1 h-3 w-3" />
            {STATUS_COPY[status]?.label ?? status}
        </Badge>
    );
}

/* ============================================================
   ACCEPT QUOTE DIALOG
============================================================ */

function AcceptQuoteDialog({open, quote, onClose, onAccepted,}: {
    open: boolean;
    quote: QuoteResponse | null;
    onClose: () => void;
    onAccepted: () => void;
}) {
    const [isSubmitting, setIsSubmitting] = useState(false);

    async function handleAccept() {
        if (!quote) return;

        setIsSubmitting(true);

        try {
            await enquiryApi.acceptQuote(quote.enquiryId, quote.id, {
                termsAccepted: true,
            });

            toast.success("Quote accepted — follow the payment steps below.");
            onAccepted();
        } catch (err) {
            toast.error(
                getApiErrorMessage(
                    err,
                    "Couldn't accept the quote. Please try again."
                )
            );
        } finally {
            setIsSubmitting(false);
        }
    }

    if (!quote) return null;

    return (
        <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
            <DialogContent className="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle className="font-display text-xl">Accept your quote</DialogTitle>
                    <DialogDescription>
                        Confirm your travel dates to secure this booking.
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-2">
                    <div className="rounded-xl border border-coral/15 bg-coral/[0.05] p-4">
                        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-coral">
                            Quote total
                        </p>

                        <p className="mt-1 font-display text-2xl font-semibold">
                            {quote.currency} {quote.totalPrice.toLocaleString()}
                        </p>

                        <p className="mt-1 text-xs text-muted-foreground">
                            {quote.currency}{" "}
                            {quote.pricePerAdult.toLocaleString()}
                            /adult
                            {quote.pricePerChild
                                ? ` · ${quote.currency} ${quote.pricePerChild.toLocaleString()}/child`
                                : ""}
                        </p>
                    </div>

                    <div className="rounded-xl border border-border/70 bg-muted/30 p-4">
                        <div className="flex gap-3">
                            <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />

                            <div>
                                <p className="text-sm font-semibold">
                                    Payment terms
                                </p>

                                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                                    By accepting this quote, you confirm that you
                                    agree to the quoted price and the payment terms.
                                    Payment instructions will be provided after
                                    acceptance.
                                </p>
                            </div>
                        </div>
                    </div>

                    {quote.validUntil && (
                        <p className="text-center text-xs text-muted-foreground">
                            Quote valid until{" "}
                            <span className="font-medium text-foreground">
                {formatDate(quote.validUntil)}
            </span>
                        </p>
                    )}
                </div>

                <DialogFooter>
                    <Button
                        variant="outline"
                        onClick={onClose}
                        disabled={isSubmitting}
                    >
                        Cancel
                    </Button>

                    <Button
                        variant="accent"
                        onClick={handleAccept}
                        disabled={isSubmitting}
                    >
                        {isSubmitting ? (
                            <>
                                <RefreshCw className="h-4 w-4 animate-spin" />
                                Accepting…
                            </>
                        ) : (
                            <>
                                <Check className="h-4 w-4" />
                                Accept quote
                            </>
                        )}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

/* ============================================================
   ENQUIRY DETAIL VIEW
============================================================ */

function EnquiryDetailPanel({
                                detail, onBack, onRefresh,
                            }: {
    detail: EnquiryDetailResponse;
    onBack: () => void;
    onRefresh: () => void;
}) {
    const [acceptingQuote, setAcceptingQuote] = useState<QuoteResponse | null>(null);

    const statusInfo = STATUS_COPY[detail.status];
    const latestSentQuote = detail.quotes.find((q) => q.status === "SENT");

    return (
        <div className="space-y-6">
            <button
                type="button"
                onClick={onBack}
                className="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
                <ArrowLeft className="h-3.5 w-3.5" />
                Back to my enquiries
            </button>

            <Card className="overflow-hidden border-border/70">
                <CardContent className="p-6">
                    <div className="flex items-start justify-between gap-4">
                        <div>
                            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                                <MapPin className="h-3.5 w-3.5 text-coral" />
                                {detail.tourName}
                            </div>
                            <h1 className="mt-2 font-display text-2xl font-semibold tracking-tight">
                                {statusInfo?.label ?? detail.status}
                            </h1>
                            <p className="mt-1.5 text-sm text-muted-foreground">{statusInfo?.blurb}</p>
                        </div>
                        <StatusBadge status={detail.status} />
                    </div>
                </CardContent>
            </Card>

            {latestSentQuote && (
                <Card className="border-coral/25 bg-coral/[0.04]">
                    <CardContent className="p-5">
                        <div className="flex items-start justify-between gap-4">
                            <div>
                                <p className="text-xs font-semibold uppercase tracking-[0.1em] text-coral">
                                    Your quote is ready
                                </p>
                                <p className="mt-1.5 font-display text-2xl font-semibold">
                                    {latestSentQuote.currency} {latestSentQuote.totalPrice.toLocaleString()}
                                </p>
                                <p className="mt-1 text-xs text-muted-foreground">
                                    {latestSentQuote.currency} {latestSentQuote.pricePerAdult.toLocaleString()}/adult
                                    {latestSentQuote.pricePerChild ? ` · ${latestSentQuote.currency} ${latestSentQuote.pricePerChild.toLocaleString()}/child` : ""}
                                    {" · valid until "}{formatDate(latestSentQuote.validUntil)}
                                </p>
                                {latestSentQuote.inclusionsNote && (
                                    <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-foreground/80">
                                        {latestSentQuote.inclusionsNote}
                                    </p>
                                )}
                            </div>
                        </div>
                        <div className="mt-4 flex flex-col gap-2 sm:flex-row">
                            <Button
                                variant="accent"
                                className="flex-1"
                                onClick={() => setAcceptingQuote(latestSentQuote)}
                            >
                                <Check className="h-4 w-4" />
                                Accept this quote
                            </Button>

                            <Button
                                variant="outline"
                                className="flex-1"
                                onClick={() =>
                                    handleDownloadQuotePdf(
                                        detail.id,
                                        latestSentQuote.id
                                    )
                                }
                            >
                                Download PDF
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            )}

            <Card>
                <CardContent className="space-y-4 p-5">
                    <p className="text-xs font-semibold uppercase tracking-[0.1em] text-muted-foreground">
                        Your request
                    </p>
                    <div className="grid grid-cols-2 gap-x-5 gap-y-4">
                        <div>
                            <p className="text-xs text-muted-foreground">Preferred date</p>
                            <p className="mt-1 inline-flex items-center gap-1.5 text-sm font-medium">
                                <CalendarDays className="h-3.5 w-3.5" /> {formatDate(detail.preferredDate)}
                            </p>
                            {detail.flexibleDates && <p className="mt-0.5 text-xs text-coral">Flexible dates</p>}
                        </div>
                        <div>
                            <p className="text-xs text-muted-foreground">Travellers</p>
                            <p className="mt-1 inline-flex items-center gap-1.5 text-sm font-medium">
                                <Users className="h-3.5 w-3.5" />
                                {detail.groupSizeAdults ?? 0} adults
                                {detail.groupSizeChildren ? `, ${detail.groupSizeChildren} children` : ""}
                            </p>
                        </div>
                        {detail.budgetRange && (
                            <div>
                                <p className="text-xs text-muted-foreground">Budget</p>
                                <p className="mt-1 inline-flex items-center gap-1.5 text-sm font-medium">
                                    <Wallet className="h-3.5 w-3.5" /> {detail.budgetRange}
                                </p>
                            </div>
                        )}
                        {detail.travelStartDate && detail.travelEndDate && (
                            <div>
                                <p className="text-xs text-muted-foreground">Confirmed dates</p>
                                <p className="mt-1 text-sm font-medium">
                                    {formatDate(detail.travelStartDate)} – {formatDate(detail.travelEndDate)}
                                </p>
                            </div>
                        )}
                        {detail.bookingReference && (
                            <div>
                                <p className="text-xs text-muted-foreground">Booking reference</p>
                                <p className="mt-1 text-sm font-medium">{detail.bookingReference}</p>
                            </div>
                        )}
                    </div>

                    {detail.requirements && (
                        <>
                            <Separator />
                            <div>
                                <p className="text-xs text-muted-foreground">Your message</p>
                                <p className="mt-1.5 whitespace-pre-wrap text-sm leading-6">{detail.requirements}</p>
                            </div>
                        </>
                    )}
                </CardContent>
            </Card>

            {detail.quotes.filter((q) => q.status !== "SENT").length > 0 && (
                <Card>
                    <CardContent className="space-y-3 p-5">
                        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-muted-foreground">
                            Quote history
                        </p>
                        {detail.quotes.filter((q) => q.status !== "SENT").map((q) => (
                            <div
                                key={q.id}
                                className="flex items-center justify-between gap-3 rounded-lg border border-border/60 p-3"
                            >
                                <div>
                                    <p className="text-sm font-medium">
                                        {q.currency} {q.totalPrice.toLocaleString()}
                                    </p>

                                    <p className="text-xs text-muted-foreground">
                                        Valid until {formatDate(q.validUntil)}
                                    </p>
                                </div>

                                <div className="flex items-center gap-2">
                                    <Badge
                                        variant="outline"
                                        className="text-[10px]"
                                    >
                                        {q.status}
                                    </Badge>

                                    <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() =>
                                            handleDownloadQuotePdf(
                                                detail.id,
                                                q.id
                                            )
                                        }
                                    >
                                        <Download className="h-4 w-4" />
                                        PDF
                                    </Button>
                                </div>
                            </div>
                        ))}
                    </CardContent>
                </Card>
            )}

            {detail.activity.length > 0 && (
                <Card>
                    <CardContent className="space-y-4 p-5">
                        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-muted-foreground">
                            Timeline
                        </p>
                        <div className="space-y-4">
                            {detail.activity.map((event) => (
                                <div key={event.id} className="flex gap-3">
                                    <div className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-coral" />
                                    <div className="min-w-0 flex-1">
                                        <p className="text-sm">{event.note || event.action.replace(/_/g, " ").toLowerCase()}</p>
                                        <p className="mt-0.5 text-[11px] text-muted-foreground">{formatDate(event.createdDate)}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            <Card className="bg-muted/30">
                <CardContent className="flex flex-wrap items-center justify-between gap-3 p-5">
                    <p className="text-sm text-muted-foreground">Questions about this enquiry?</p>
                    <div className="flex gap-2">
                        <Button variant="outline" size="sm" asChild>
                            <a href="mailto:support@damuchi.com"><Mail className="h-3.5 w-3.5" /> Email us</a>
                        </Button>
                        <Button variant="outline" size="sm" asChild>
                            <a href="https://wa.me/254700000000" target="_blank" rel="noreferrer">
                                <MessageCircle className="h-3.5 w-3.5" /> WhatsApp
                            </a>
                        </Button>
                    </div>
                </CardContent>
            </Card>

            <AcceptQuoteDialog
                open={!!acceptingQuote}
                quote={acceptingQuote}
                onClose={() => setAcceptingQuote(null)}
                onAccepted={() => { setAcceptingQuote(null); onRefresh(); }}
            />
        </div>
    );
}

/* ============================================================
   PAGE
============================================================ */

export default function MyEnquiriesPage() {
    const [enquiries, setEnquiries] = useState<EnquirySummaryResponse[]>([]);
    const [page, setPage] = useState(0);
    const [totalPages, setTotalPages] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [statusFilter, setStatusFilter] = useState<TourEnquiryStatus | "ALL">("ALL");

    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [detail, setDetail] = useState<EnquiryDetailResponse | null>(null);
    const [detailLoading, setDetailLoading] = useState(false);

    const load = useCallback(async (targetPage = 0) => {
        setIsLoading(true);
        setLoadError(null);
        try {
            const data = await enquiryApi.myEnquiries(
                statusFilter === "ALL" ? undefined : statusFilter,
                targetPage,
                PAGE_SIZE,
            );
            setEnquiries(Array.isArray(data?.content) ? data.content : []);
            setTotalPages(data?.totalPages ?? 0);
            setPage(targetPage);
        } catch (err) {
            const message = getApiErrorMessage(err, "Couldn't load your enquiries.");
            setLoadError(message);
            setEnquiries([]);
        } finally {
            setIsLoading(false);
        }
    }, [statusFilter]);

    useEffect(() => { load(0); }, [load]);

    const openDetail = useCallback(async (id: string) => {
        setSelectedId(id);
        setDetailLoading(true);
        try {
            const data = await enquiryApi.myEnquiryDetail(id);
            setDetail(data);
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't load this enquiry."));
            setSelectedId(null);
        } finally {
            setDetailLoading(false);
        }
    }, []);

    async function refreshDetail() {
        if (!selectedId) return;
        const data = await enquiryApi.myEnquiryDetail(selectedId);
        setDetail(data);
        load(page);
    }

    const hasNeedsAttention = useMemo(
        () => enquiries.some((e) => e.status === "QUOTED"),
        [enquiries],
    );

    // ── Detail view — same Navbar/main/Footer shell as the list view below ──
    if (selectedId) {
        return (
            <PageShell>
                <div className="mx-auto max-w-2xl">
                    {detailLoading || !detail ? (
                        <div className="space-y-3">
                            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 w-full rounded-2xl" />)}
                        </div>
                    ) : (
                        <EnquiryDetailPanel
                            detail={detail}
                            onBack={() => { setSelectedId(null); setDetail(null); }}
                            onRefresh={refreshDetail}
                        />
                    )}
                </div>
            </PageShell>
        );
    }

    return (
        <PageShell>
            <div className="mx-auto max-w-3xl space-y-6">
                <PageHeader
                    eyebrow="Your trips"
                    title="My enquiries"
                    subtitle={
                        isLoading
                            ? "Loading…"
                            : hasNeedsAttention
                                ? "You have a quote waiting for your response"
                                : "Track your safari enquiries and quotes"
                    }
                    action={
                        <Button variant="outline" size="sm" onClick={() => load(page)} disabled={isLoading}>
                            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
                            Refresh
                        </Button>
                    }
                />

                <div className="flex items-center gap-2">
                    <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as TourEnquiryStatus | "ALL")}>
                        <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
                        <SelectContent>
                            <SelectItem value="ALL">All enquiries</SelectItem>
                            {FILTERABLE_STATUSES.map((s) => (
                                <SelectItem key={s} value={s}>{STATUS_COPY[s].label}</SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>

                {isLoading ? (
                    <div className="space-y-3">
                        {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28 w-full rounded-2xl" />)}
                    </div>
                ) : loadError ? (
                    <EmptyState icon={AlertTriangle} title="Couldn't load your enquiries" description={loadError} />
                ) : enquiries.length === 0 ? (
                    <EmptyState
                        icon={Inbox}
                        title="No enquiries yet"
                        description="Browse our tours and send an enquiry to start planning your trip."
                    />
                ) : (
                    <div className="space-y-3">
                        {enquiries.map((enquiry) => (
                            <Card
                                key={enquiry.id}
                                className="cursor-pointer border-border/70 transition-all hover:-translate-y-0.5 hover:border-coral/30 hover:shadow-md"
                                onClick={() => openDetail(enquiry.id)}
                            >
                                <CardContent className="flex items-center justify-between gap-4 p-5">
                                    <div className="min-w-0">
                                        <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-[0.1em] text-muted-foreground">
                                            <MapPin className="h-3.5 w-3.5 text-coral" />
                                            <span className="truncate">{enquiry.tourName}</span>
                                        </div>
                                        <p className="mt-1.5 text-sm text-muted-foreground">
                                            Sent {formatDate(enquiry.createdDate)}
                                        </p>
                                    </div>
                                    <StatusBadge status={enquiry.status} />
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                )}

                {totalPages > 1 && (
                    <div className="flex justify-center gap-2 pt-2">
                        <Button variant="outline" size="sm" onClick={() => load(page - 1)} disabled={page === 0 || isLoading}>
                            Previous
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => load(page + 1)} disabled={page + 1 >= totalPages || isLoading}>
                            Next
                        </Button>
                    </div>
                )}
            </div>
        </PageShell>
    );
}