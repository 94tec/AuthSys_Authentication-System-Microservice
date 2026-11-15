"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
    AlertTriangle,
    ArrowDownToLine,
    ArrowLeft,
    ArrowRight,
    CalendarDays,
    Check,
    CheckCircle2,
    ChevronRight,
    Clock3,
    Copy,
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

import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

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
   CONFIGURATION
============================================================ */

const PAGE_SIZE = 12;

const FILTERABLE_STATUSES: TourEnquiryStatus[] = [
    "NEW",
    "CONTACTED",
    "QUOTED",
    "CONVERTED",
    "COMPLETED",
    "LOST",
];

/** Happy-path journey shown in the progress tracker. */
const JOURNEY: TourEnquiryStatus[] = [
    "NEW",
    "CONTACTED",
    "QUOTED",
    "CONVERTED",
    "COMPLETED",
];

const STATUS_COPY: Record<
    TourEnquiryStatus,
    { label: string; description: string }
> = {
    NEW: {
        label: "Received",
        description: "We've received your enquiry and will be in touch shortly.",
    },
    CONTACTED: {
        label: "In conversation",
        description: "A safari specialist is working on your trip.",
    },
    QUOTED: {
        label: "Quote ready",
        description: "Your personalised quote is ready to review.",
    },
    CONVERTED: {
        label: "Booked",
        description: "Your trip is confirmed. We can't wait to host you.",
    },
    COMPLETED: {
        label: "Completed",
        description: "We hope you had an unforgettable journey.",
    },
    LOST: {
        label: "Closed",
        description: "This enquiry is no longer active.",
    },
    ARCHIVED: {
        label: "Archived",
        description: "This enquiry has been archived.",
    },
};

const STATUS_STYLES: Record<TourEnquiryStatus, string> = {
    NEW: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-400",
    CONTACTED:
        "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900/60 dark:bg-blue-950/30 dark:text-blue-400",
    QUOTED: "border-coral/30 bg-coral/10 text-coral",
    CONVERTED:
        "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-400",
    COMPLETED:
        "border-teal-200 bg-teal-50 text-teal-700 dark:border-teal-900/60 dark:bg-teal-950/30 dark:text-teal-400",
    LOST: "border-red-200 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-400",
    ARCHIVED: "border-border bg-muted text-muted-foreground",
};

const STATUS_ICONS: Record<TourEnquiryStatus, React.ElementType> = {
    NEW: Inbox,
    CONTACTED: Clock3,
    QUOTED: Send,
    CONVERTED: Sparkles,
    COMPLETED: CheckCircle2,
    LOST: XCircle,
    ARCHIVED: XCircle,
};

const ENTER =
    "animate-in fade-in slide-in-from-bottom-2 duration-500 motion-reduce:animate-none";

/* ============================================================
   HELPERS
============================================================ */

function getApiErrorMessage(err: unknown, fallback: string) {
    return (err as ApiError)?.message || fallback;
}

function formatDate(iso?: string) {
    if (!iso) return "—";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "—";

    return date.toLocaleDateString("en-GB", {
        day: "numeric",
        month: "short",
        year: "numeric",
    });
}

function formatAmount(amount: number, currency: string) {
    return `${currency} ${Number(amount || 0).toLocaleString()}`;
}

async function handleDownloadQuotePdf(enquiryId: string, quoteId: string) {
    try {
        const blob = await enquiryApi.downloadQuotePdf(enquiryId, quoteId, true);

        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");

        anchor.href = url;
        anchor.download = `quote-${quoteId}.pdf`;

        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        window.setTimeout(() => URL.revokeObjectURL(url), 1000);

        toast.success("Your quote PDF has been downloaded.");
    } catch (err) {
        toast.error(getApiErrorMessage(err, "Couldn't download your quote PDF."));
    }
}

async function copyText(value: string, message: string) {
    try {
        await navigator.clipboard.writeText(value);
        toast.success(message);
    } catch {
        toast.error("Couldn't copy to clipboard.");
    }
}

/**
 * The parent app/me/layout.tsx owns the shared Navbar,
 * account navigation, page container and Footer.
 * Customer pages must only render their own content.
 */
function PageShell({ children }: { children: React.ReactNode }) {
    return <>{children}</>;
}

/* ============================================================
   SMALL PIECES
============================================================ */

function StatusBadge({ status }: { status: TourEnquiryStatus }) {
    const Icon = STATUS_ICONS[status] ?? Inbox;

    return (
        <Badge
            variant="outline"
            className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1 text-[10px] font-bold tracking-wide ${STATUS_STYLES[status]}`}
        >
            <Icon className="h-3 w-3" />
            {STATUS_COPY[status]?.label ?? status}
        </Badge>
    );
}

function SectionLabel({
                          children,
                          trailing,
                      }: {
    children: React.ReactNode;
    trailing?: React.ReactNode;
}) {
    return (
        <div className="flex items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-sm font-bold tracking-tight text-foreground">
                <span className="h-4 w-1 rounded-full bg-coral" aria-hidden="true" />
                {children}
            </h2>
            {trailing}
        </div>
    );
}

function HeroBackdrop() {
    return (
        <>
            <div
                className="pointer-events-none absolute inset-0 opacity-[0.12]"
                style={{
                    backgroundImage:
                        "radial-gradient(circle at 1px 1px, rgba(255,255,255,0.6) 1px, transparent 0)",
                    backgroundSize: "22px 22px",
                }}
                aria-hidden="true"
            />
            <div className="pointer-events-none absolute -right-16 -top-20 h-56 w-56 rounded-full border border-white/10" />
            <div className="pointer-events-none absolute -right-5 -top-9 h-36 w-36 rounded-full border border-white/10" />
            <div className="pointer-events-none absolute -bottom-24 left-1/4 h-52 w-52 rounded-full bg-coral/15 blur-3xl" />
        </>
    );
}

/** Visual journey tracker: Received → Conversation → Quote → Booked → Completed */
function ProgressTracker({ status }: { status: TourEnquiryStatus }) {
    const closed = status === "LOST" || status === "ARCHIVED";
    const current = JOURNEY.indexOf(status);

    if (closed) {
        return (
            <div className="flex items-center gap-3 rounded-xl border border-white/15 bg-white/[0.08] px-4 py-3 text-xs text-white/75">
                <XCircle className="h-4 w-4 shrink-0 text-white/60" />
                {STATUS_COPY[status].description}
            </div>
        );
    }

    return (
        <ol
            className="grid grid-cols-5 gap-1"
            aria-label="Enquiry progress"
        >
            {JOURNEY.map((step, index) => {
                const done = index < current;
                const active = index === current;

                return (
                    <li key={step} className="relative flex flex-col items-center gap-2 text-center">
                        {index > 0 && (
                            <span
                                className={`absolute right-1/2 top-[11px] h-0.5 w-full -translate-y-1/2 rounded-full ${
                                    index <= current ? "bg-coral" : "bg-white/15"
                                }`}
                                aria-hidden="true"
                            />
                        )}

                        <span
                            className={`relative z-10 flex h-[22px] w-[22px] items-center justify-center rounded-full border-2 transition-colors ${
                                done
                                    ? "border-coral bg-coral text-white"
                                    : active
                                        ? "border-coral bg-forest-950 text-coral ring-4 ring-coral/20"
                                        : "border-white/20 bg-forest-950 text-transparent"
                            }`}
                        >
                            {done ? (
                                <Check className="h-3 w-3" />
                            ) : (
                                <span
                                    className={`h-1.5 w-1.5 rounded-full ${
                                        active ? "bg-coral" : "bg-transparent"
                                    }`}
                                />
                            )}
                        </span>

                        <span
                            className={`text-[9px] font-semibold leading-tight sm:text-[11px] ${
                                active
                                    ? "text-white"
                                    : done
                                        ? "text-white/70"
                                        : "text-white/35"
                            }`}
                        >
                            {STATUS_COPY[step].label}
                        </span>
                    </li>
                );
            })}
        </ol>
    );
}

function DetailItem({
                        icon: Icon,
                        label,
                        children,
                    }: {
    icon: React.ElementType;
    label: string;
    children: React.ReactNode;
}) {
    return (
        <div className="flex min-w-0 items-start gap-3 rounded-2xl border border-border/60 bg-background p-3.5 transition-colors hover:border-coral/25">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-coral/10 text-coral">
                <Icon className="h-4 w-4" />
            </span>

            <div className="min-w-0">
                <p className="text-[11px] font-medium text-muted-foreground">
                    {label}
                </p>
                <div className="mt-1 break-words text-sm font-semibold text-foreground">
                    {children}
                </div>
            </div>
        </div>
    );
}

function PriceBreakdown({ quote }: { quote: QuoteResponse }) {
    return (
        <p className="mt-2 text-xs leading-5 text-muted-foreground">
            {formatAmount(quote.pricePerAdult, quote.currency)}
            {" / adult"}
            {quote.pricePerChild
                ? ` · ${formatAmount(quote.pricePerChild, quote.currency)} / child`
                : ""}
        </p>
    );
}

function SupportCard({ title, text }: { title: string; text: string }) {
    return (
        <section className="rounded-2xl border border-border/70 bg-gradient-to-br from-muted/40 to-background p-5 sm:p-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                    <p className="font-semibold text-foreground">{title}</p>
                    <p className="mt-1 text-sm leading-6 text-muted-foreground">
                        {text}
                    </p>
                </div>

                <div className="grid grid-cols-2 gap-2 sm:flex">
                    <Button
                        variant="outline"
                        size="sm"
                        className="h-10 rounded-xl bg-background"
                        asChild
                    >
                        <a href="mailto:support@damuchi.com">
                            <Mail className="h-3.5 w-3.5" />
                            Email us
                        </a>
                    </Button>

                    <Button
                        variant="outline"
                        size="sm"
                        className="h-10 rounded-xl bg-background"
                        asChild
                    >
                        <a
                            href="https://wa.me/254700000000"
                            target="_blank"
                            rel="noreferrer"
                        >
                            <MessageCircle className="h-3.5 w-3.5" />
                            WhatsApp
                        </a>
                    </Button>
                </div>
            </div>
        </section>
    );
}

/* ============================================================
   ACCEPT QUOTE DIALOG
============================================================ */

function AcceptQuoteDialog({
                               open,
                               quote,
                               onClose,
                               onAccepted,
                           }: {
    open: boolean;
    quote: QuoteResponse | null;
    onClose: () => void;
    onAccepted: () => void;
}) {
    const [isSubmitting, setIsSubmitting] = useState(false);

    async function handleAccept() {
        if (!quote || isSubmitting) return;

        setIsSubmitting(true);

        try {
            await enquiryApi.acceptQuote(quote.enquiryId, quote.id, {
                termsAccepted: true,
            });

            toast.success(
                "Quote accepted. Follow the payment instructions provided by our team.",
            );

            onAccepted();
        } catch (err) {
            toast.error(
                getApiErrorMessage(
                    err,
                    "Couldn't accept the quote. Please try again.",
                ),
            );
        } finally {
            setIsSubmitting(false);
        }
    }

    if (!quote) return null;

    return (
        <Dialog open={open} onOpenChange={(value) => !value && onClose()}>
            <DialogContent className="max-h-[92dvh] w-[calc(100%-2rem)] overflow-y-auto rounded-3xl p-0 sm:max-w-md">
                <div className="relative overflow-hidden bg-gradient-to-br from-forest-950 via-forest-900 to-emerald-950 px-6 py-7 text-white">
                    <HeroBackdrop />

                    <div className="relative">
                        <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-2xl border border-white/15 bg-white/10 backdrop-blur-sm">
                            <Sparkles className="h-5 w-5 text-coral" />
                        </div>

                        <DialogHeader className="text-left">
                            <DialogTitle className="font-display text-2xl font-semibold text-white">
                                Ready for your adventure?
                            </DialogTitle>
                            <DialogDescription className="mt-2 text-sm leading-6 text-white/70">
                                Review your quote and confirm that you would
                                like to proceed.
                            </DialogDescription>
                        </DialogHeader>
                    </div>
                </div>

                <div className="space-y-5 p-5 sm:p-6">
                    <div className="rounded-2xl border border-coral/20 bg-gradient-to-br from-coral/[0.08] to-transparent p-4">
                        <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-coral">
                            Your quoted total
                        </p>

                        <p className="mt-2 font-display text-3xl font-semibold tracking-tight text-foreground">
                            {formatAmount(quote.totalPrice, quote.currency)}
                        </p>

                        <PriceBreakdown quote={quote} />
                    </div>

                    <div className="flex gap-3 rounded-2xl border border-border/70 bg-muted/30 p-4">
                        <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />

                        <div>
                            <p className="text-sm font-semibold">Payment terms</p>
                            <p className="mt-1 text-xs leading-5 text-muted-foreground">
                                By accepting this quote, you confirm that you
                                agree to the quoted price and payment terms.
                                Payment instructions will be provided after
                                acceptance.
                            </p>
                        </div>
                    </div>

                    {quote.validUntil && (
                        <p className="text-center text-xs text-muted-foreground">
                            This quote is valid until{" "}
                            <span className="font-semibold text-foreground">
                                {formatDate(quote.validUntil)}
                            </span>
                        </p>
                    )}

                    <DialogFooter className="flex-col-reverse gap-2 sm:flex-row">
                        <Button
                            type="button"
                            variant="outline"
                            onClick={onClose}
                            disabled={isSubmitting}
                            className="h-11 w-full rounded-xl sm:w-auto"
                        >
                            Not now
                        </Button>

                        <Button
                            type="button"
                            variant="accent"
                            onClick={handleAccept}
                            disabled={isSubmitting}
                            className="h-11 w-full rounded-xl shadow-sm sm:flex-1"
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
                </div>
            </DialogContent>
        </Dialog>
    );
}

/* ============================================================
   ENQUIRY DETAIL VIEW
============================================================ */

function EnquiryDetailPanel({
                                detail,
                                onBack,
                                onRefresh,
                            }: {
    detail: EnquiryDetailResponse;
    onBack: () => void;
    onRefresh: () => void;
}) {
    const [acceptingQuote, setAcceptingQuote] =
        useState<QuoteResponse | null>(null);

    const statusInfo = STATUS_COPY[detail.status];
    const latestSentQuote = detail.quotes.find((q) => q.status === "SENT");
    const previousQuotes = detail.quotes.filter((q) => q.status !== "SENT");

    return (
        <div className={`space-y-5 sm:space-y-6 ${ENTER}`}>
            <button
                type="button"
                onClick={onBack}
                className="group inline-flex items-center gap-2 rounded-lg py-1 text-xs font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coral"
            >
                <span className="flex h-9 w-9 items-center justify-center rounded-full border border-border bg-background transition-all group-hover:-translate-x-0.5 group-hover:border-coral/40 group-hover:bg-coral/5">
                    <ArrowLeft className="h-4 w-4" />
                </span>
                Back to my enquiries
            </button>

            {/* Hero */}
            <section className="relative isolate overflow-hidden rounded-3xl bg-gradient-to-br from-forest-950 via-forest-900 to-emerald-950 p-5 text-white shadow-xl shadow-forest-950/10 sm:p-8">
                <HeroBackdrop />

                <div className="relative isolate overflow-hidden rounded-3xl bg-gradient-to-br from-forest-950 via-forest-900 to-emerald-950 p-5 text-white shadow-xl shadow-forest-950/10 sm:p-8">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                        <span className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3 py-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-white/80 backdrop-blur-sm">
                            <MapPin className="h-3 w-3 text-coral" />
                            Your safari enquiry
                        </span>

                        <StatusBadge status={detail.status} />
                    </div>

                    <h1 className="mt-5 max-w-2xl text-balance font-display text-2xl font-semibold leading-tight tracking-tight sm:text-4xl">
                        {detail.tourName}
                    </h1>

                    <p className="mt-2 max-w-lg text-sm leading-6 text-white/65">
                        {statusInfo?.description ??
                            "Track the progress of your safari enquiry."}
                    </p>

                    <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-white/60">
                        <span className="inline-flex items-center gap-1.5">
                            <CalendarDays className="h-3.5 w-3.5" />
                            Submitted {formatDate(detail.createdDate)}
                        </span>

                        {detail.bookingReference && (
                            <button
                                type="button"
                                onClick={() =>
                                    copyText(
                                        detail.bookingReference!,
                                        "Booking reference copied.",
                                    )
                                }
                                className="inline-flex items-center gap-1.5 rounded-full border border-white/15 bg-white/10 px-2.5 py-1 font-semibold text-white/85 transition-colors hover:bg-white/15"
                                aria-label="Copy booking reference"
                            >
                                Ref: {detail.bookingReference}
                                <Copy className="h-3 w-3" />
                            </button>
                        )}
                    </div>

                    <div className="mt-7 rounded-2xl border border-white/10 bg-black/10 p-4 backdrop-blur-sm sm:p-5">
                        <ProgressTracker status={detail.status} />
                    </div>
                </div>
            </section>

            {/* Quote ready */}
            {latestSentQuote && (
                <section className="relative overflow-hidden rounded-3xl border border-coral/30 bg-gradient-to-br from-coral/[0.11] via-background to-background p-5 shadow-lg shadow-coral/5 sm:p-7">
                    <div className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full bg-coral/[0.1] blur-3xl" />

                    <div className="relative">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                                <div className="inline-flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.16em] text-coral">
                                    <Sparkles className="h-3.5 w-3.5" />
                                    Your personalised quote is ready
                                </div>

                                <p className="mt-3 font-display text-4xl font-semibold tracking-tight text-foreground sm:text-5xl">
                                    {formatAmount(
                                        latestSentQuote.totalPrice,
                                        latestSentQuote.currency,
                                    )}
                                </p>

                                <PriceBreakdown quote={latestSentQuote} />
                            </div>

                            <Badge
                                variant="outline"
                                className="rounded-full border-coral/30 bg-coral/10 px-3 py-1 text-[10px] font-bold text-coral"
                            >
                                Awaiting response
                            </Badge>
                        </div>

                        {latestSentQuote.inclusionsNote && (
                            <div className="mt-5 rounded-2xl border border-border/60 bg-background/80 p-4 backdrop-blur-sm">
                                <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
                                    What's included
                                </p>
                                <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-foreground/80">
                                    {latestSentQuote.inclusionsNote}
                                </p>
                            </div>
                        )}

                        {latestSentQuote.validUntil && (
                            <p className="mt-4 inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                                <Clock3 className="h-3.5 w-3.5" />
                                Valid until{" "}
                                <span className="font-semibold text-foreground">
                                    {formatDate(latestSentQuote.validUntil)}
                                </span>
                            </p>
                        )}

                        <div className="mt-6 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                            <Button
                                type="button"
                                variant="accent"
                                className="h-12 w-full rounded-xl text-sm font-semibold shadow-md transition-transform active:scale-[0.99]"
                                onClick={() => setAcceptingQuote(latestSentQuote)}
                            >
                                <CheckCircle2 className="h-4 w-4" />
                                Accept this quote
                            </Button>

                            <Button
                                type="button"
                                variant="outline"
                                className="h-12 w-full rounded-xl bg-background/80"
                                onClick={() =>
                                    handleDownloadQuotePdf(
                                        detail.id,
                                        latestSentQuote.id,
                                    )
                                }
                            >
                                <ArrowDownToLine className="h-4 w-4" />
                                Download quote PDF
                            </Button>
                        </div>
                    </div>
                </section>
            )}

            {/* Trip details */}
            <Card className="overflow-hidden rounded-3xl border-border/70 shadow-sm">
                <CardContent className="p-5 sm:p-7">
                    <SectionLabel>Trip details</SectionLabel>

                    <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <DetailItem icon={CalendarDays} label="Preferred travel date">
                            {formatDate(detail.preferredDate)}
                            {detail.flexibleDates && (
                                <span className="ml-2 rounded-full bg-coral/10 px-2 py-0.5 text-[10px] font-semibold text-coral">
                                    Flexible
                                </span>
                            )}
                        </DetailItem>

                        <DetailItem icon={Users} label="Travellers">
                            {detail.groupSizeAdults ?? 0} adults
                            {detail.groupSizeChildren
                                ? `, ${detail.groupSizeChildren} children`
                                : ""}
                        </DetailItem>

                        {detail.budgetRange && (
                            <DetailItem icon={Wallet} label="Budget range">
                                {detail.budgetRange}
                            </DetailItem>
                        )}

                        {detail.travelStartDate && detail.travelEndDate && (
                            <DetailItem icon={CalendarDays} label="Confirmed travel dates">
                                {formatDate(detail.travelStartDate)} –{" "}
                                {formatDate(detail.travelEndDate)}
                            </DetailItem>
                        )}

                        {detail.bookingReference && (
                            <DetailItem icon={CheckCircle2} label="Booking reference">
                                {detail.bookingReference}
                            </DetailItem>
                        )}
                    </div>

                    {detail.requirements && (
                        <>
                            <Separator className="my-6" />

                            <div>
                                <p className="text-xs font-bold uppercase tracking-[0.12em] text-muted-foreground">
                                    Your message
                                </p>
                                <p className="mt-3 whitespace-pre-wrap rounded-2xl bg-muted/30 p-4 text-sm leading-7 text-foreground/80">
                                    {detail.requirements}
                                </p>
                            </div>
                        </>
                    )}
                </CardContent>
            </Card>

            {/* Quote history */}
            {previousQuotes.length > 0 && (
                <Card className="overflow-hidden rounded-3xl border-border/70 shadow-sm">
                    <CardContent className="p-5 sm:p-7">
                        <SectionLabel>Quote history</SectionLabel>

                        <div className="mt-5 space-y-3">
                            {previousQuotes.map((quote) => (
                                <div
                                    key={quote.id}
                                    className="flex flex-col gap-3 rounded-2xl border border-border/70 bg-muted/20 p-4 transition-colors hover:bg-muted/40 sm:flex-row sm:items-center sm:justify-between"
                                >
                                    <div className="min-w-0">
                                        <p className="font-display text-lg font-semibold">
                                            {formatAmount(
                                                quote.totalPrice,
                                                quote.currency,
                                            )}
                                        </p>

                                        <p className="mt-1 text-xs text-muted-foreground">
                                            Valid until {formatDate(quote.validUntil)}
                                        </p>
                                    </div>

                                    <div className="flex flex-wrap items-center gap-2">
                                        <Badge
                                            variant="outline"
                                            className="rounded-full text-[10px]"
                                        >
                                            {quote.status.replace(/_/g, " ")}
                                        </Badge>

                                        <Button
                                            type="button"
                                            size="sm"
                                            variant="outline"
                                            className="h-9 rounded-lg"
                                            onClick={() =>
                                                handleDownloadQuotePdf(
                                                    detail.id,
                                                    quote.id,
                                                )
                                            }
                                        >
                                            <ArrowDownToLine className="h-3.5 w-3.5" />
                                            PDF
                                        </Button>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* Activity */}
            {detail.activity.length > 0 && (
                <Card className="overflow-hidden rounded-3xl border-border/70 shadow-sm">
                    <CardContent className="p-5 sm:p-7">
                        <SectionLabel>Enquiry activity</SectionLabel>

                        <div className="mt-6">
                            {detail.activity.map((event, index) => (
                                <div
                                    key={event.id}
                                    className="relative flex gap-4 pb-6 last:pb-0"
                                >
                                    {index !== detail.activity.length - 1 && (
                                        <div className="absolute bottom-0 left-[7px] top-5 w-px bg-gradient-to-b from-coral/40 to-border" />
                                    )}

                                    <div className="relative z-10 mt-1 h-3.5 w-3.5 shrink-0 rounded-full border-[3px] border-coral/30 bg-coral" />

                                    <div className="min-w-0 flex-1">
                                        <p className="text-sm font-medium leading-6 first-letter:uppercase">
                                            {event.note ||
                                                event.action
                                                    .replace(/_/g, " ")
                                                    .toLowerCase()}
                                        </p>

                                        <p className="mt-0.5 text-[11px] text-muted-foreground">
                                            {formatDate(event.createdDate)}
                                        </p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            )}

            <SupportCard
                title="Need a little help?"
                text="Our safari team is happy to help with your enquiry."
            />

            <AcceptQuoteDialog
                open={!!acceptingQuote}
                quote={acceptingQuote}
                onClose={() => setAcceptingQuote(null)}
                onAccepted={() => {
                    setAcceptingQuote(null);
                    onRefresh();
                }}
            />
        </div>
    );
}

/* ============================================================
   LOADING STATES
============================================================ */

function DetailSkeleton() {
    return (
        <div className="space-y-5">
            <Skeleton className="h-9 w-48 rounded-full" />
            <Skeleton className="h-64 w-full rounded-3xl" />
            <Skeleton className="h-48 w-full rounded-3xl" />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Skeleton className="h-20 rounded-2xl" />
                <Skeleton className="h-20 rounded-2xl" />
            </div>
        </div>
    );
}

/* ============================================================
   ENQUIRY CARD
============================================================ */

function EnquiryCard({
                         enquiry,
                         index,
                         onOpen,
                     }: {
    enquiry: EnquirySummaryResponse;
    index: number;
    onOpen: (id: string) => void;
}) {
    const isQuoted = enquiry.status === "QUOTED";

    return (
        <Card
            style={{ animationDelay: `${Math.min(index * 50, 250)}ms` }}
            className={`group relative overflow-hidden rounded-2xl border shadow-sm transition-all duration-300 hover:-translate-y-0.5 hover:shadow-xl hover:shadow-foreground/[0.05] ${ENTER} ${
                isQuoted
                    ? "border-coral/30 bg-gradient-to-br from-coral/[0.06] to-background"
                    : "border-border/70 hover:border-coral/25"
            }`}
        >
            {isQuoted && (
                <span
                    className="absolute inset-y-0 left-0 w-1 bg-gradient-to-b from-coral to-coral/40"
                    aria-hidden="true"
                />
            )}

            <CardContent className="p-0">
                <button
                    type="button"
                    onClick={() => onOpen(enquiry.id)}
                    className="w-full p-4 text-left outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-coral sm:p-5"
                    aria-label={`View enquiry for ${enquiry.tourName}`}
                >
                    <div className="flex items-start gap-3 sm:gap-4">
                        <div
                            className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl transition-transform duration-300 group-hover:scale-105 sm:h-12 sm:w-12 ${
                                isQuoted
                                    ? "bg-coral/10 text-coral"
                                    : "bg-forest-900/[0.07] text-forest-900 dark:bg-emerald-400/10 dark:text-emerald-400"
                            }`}
                        >
                            {isQuoted ? (
                                <Sparkles className="h-5 w-5" />
                            ) : (
                                <MapPin className="h-5 w-5" />
                            )}
                        </div>

                        <div className="min-w-0 flex-1">
                            <div className="flex flex-col gap-2.5 sm:flex-row sm:items-start sm:justify-between">
                                <div className="min-w-0">
                                    <h3 className="line-clamp-2 font-display text-base font-semibold leading-snug text-foreground transition-colors group-hover:text-coral sm:text-lg">
                                        {enquiry.tourName}
                                    </h3>

                                    <p className="mt-1.5 inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                                        <CalendarDays className="h-3 w-3" />
                                        Submitted {formatDate(enquiry.createdDate)}
                                    </p>
                                </div>

                                <div className="flex items-center justify-between gap-3 sm:justify-end">
                                    <StatusBadge status={enquiry.status} />

                                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border/70 text-muted-foreground transition-all group-hover:border-coral/30 group-hover:bg-coral/5 group-hover:text-coral">
                                        <ChevronRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                                    </span>
                                </div>
                            </div>

                            {isQuoted && (
                                <p className="mt-3 inline-flex items-center gap-1.5 rounded-full bg-coral/10 px-2.5 py-1 text-[11px] font-semibold text-coral">
                                    <Sparkles className="h-3 w-3" />
                                    Your quote is ready to review
                                </p>
                            )}
                        </div>
                    </div>
                </button>
            </CardContent>
        </Card>
    );
}

/* ============================================================
   FILTER CHIPS
============================================================ */

function FilterChips({
                         value,
                         onChange,
                     }: {
    value: TourEnquiryStatus | "ALL";
    onChange: (value: TourEnquiryStatus | "ALL") => void;
}) {
    const options: Array<{ value: TourEnquiryStatus | "ALL"; label: string }> = [
        { value: "ALL", label: "All" },
        ...FILTERABLE_STATUSES.map((s) => ({
            value: s,
            label: STATUS_COPY[s].label,
        })),
    ];

    return (
        <div
            role="group"
            aria-label="Filter enquiries by status"
            className="-mx-4 flex gap-2 overflow-x-auto px-4 pb-1 [scrollbar-width:none] sm:mx-0 sm:flex-wrap sm:px-0 [&::-webkit-scrollbar]:hidden"
        >
            {options.map((option) => {
                const active = option.value === value;

                return (
                    <button
                        key={option.value}
                        type="button"
                        aria-pressed={active}
                        onClick={() => onChange(option.value)}
                        className={`h-9 shrink-0 rounded-full border px-4 text-xs font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coral ${
                            active
                                ? "border-forest-900 bg-forest-900 text-white shadow-sm dark:border-emerald-600 dark:bg-emerald-700"
                                : "border-border/70 bg-background text-muted-foreground hover:border-coral/40 hover:text-foreground"
                        }`}
                    >
                        {option.label}
                    </button>
                );
            })}
        </div>
    );
}

/* ============================================================
   MAIN PAGE
============================================================ */

export default function MyEnquiriesPage() {
    const [enquiries, setEnquiries] = useState<EnquirySummaryResponse[]>([]);

    const [page, setPage] = useState(0);
    const [totalPages, setTotalPages] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);

    const [statusFilter, setStatusFilter] = useState<
        TourEnquiryStatus | "ALL"
    >("ALL");

    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [detail, setDetail] = useState<EnquiryDetailResponse | null>(null);
    const [detailLoading, setDetailLoading] = useState(false);

    const load = useCallback(
        async (targetPage = 0) => {
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
                setLoadError(
                    getApiErrorMessage(err, "Couldn't load your enquiries."),
                );
                setEnquiries([]);
            } finally {
                setIsLoading(false);
            }
        },
        [statusFilter],
    );

    useEffect(() => {
        load(0);
    }, [load]);

    const openDetail = useCallback(async (id: string) => {
        setSelectedId(id);
        setDetail(null);
        setDetailLoading(true);
        window.scrollTo({ top: 0, behavior: "smooth" });

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

    const refreshDetail = useCallback(async () => {
        if (!selectedId) return;

        try {
            const data = await enquiryApi.myEnquiryDetail(selectedId);
            setDetail(data);
            await load(page);
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't refresh this enquiry."));
        }
    }, [selectedId, page, load]);

    const summary = useMemo(
        () => ({
            total: enquiries.length,
            awaitingResponse: enquiries.filter((i) => i.status === "QUOTED")
                .length,
            inProgress: enquiries.filter(
                (i) => i.status === "NEW" || i.status === "CONTACTED",
            ).length,
        }),
        [enquiries],
    );

    const firstQuoted = enquiries.find((e) => e.status === "QUOTED");

    /* Detail view */
    if (selectedId) {
        return (
            <PageShell>
                <div className="mx-auto w-full max-w-4xl">
                    {detailLoading || !detail ? (
                        <DetailSkeleton />
                    ) : (
                        <EnquiryDetailPanel
                            detail={detail}
                            onBack={() => {
                                setSelectedId(null);
                                setDetail(null);
                            }}
                            onRefresh={refreshDetail}
                        />
                    )}
                </div>
            </PageShell>
        );
    }

    const stats = [
        {
            label: "On this page",
            value: summary.total,
            icon: Inbox,
        },
        {
            label: "In progress",
            value: summary.inProgress,
            icon: Clock3,
        },
        {
            label: "Quotes to review",
            value: summary.awaitingResponse,
            icon: Sparkles,
            highlight: true,
        },
    ];

    /* Enquiry list */
    return (
        <PageShell>
            <div className="mx-auto w-full max-w-5xl space-y-6 pb-8 sm:space-y-8">
                {/* Hero + stats */}
                <section className="relative isolate overflow-hidden rounded-3xl bg-gradient-to-br from-[#123D32] via-[#0F3329] to-[#0B2A22] p-6 text-white shadow-xl shadow-emerald-950/10 sm:p-8">
                    <HeroBackdrop />

                    <div className="relative flex flex-col gap-6 sm:gap-7">
                        <div className="flex items-start justify-between gap-4">
                            <div className="min-w-0">
                                <span className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3 py-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-white/80 backdrop-blur-sm">
                                    <Send className="h-3 w-3 text-coral" />
                                    Trip enquiries
                                </span>

                                <h1 className="mt-4 text-balance font-display text-3xl font-semibold tracking-tight sm:text-4xl">
                                    My safari enquiries
                                </h1>

                                <p className="mt-2 max-w-md text-sm leading-6 text-white/65">
                                    Follow every request from first hello to
                                    confirmed adventure.
                                </p>
                            </div>

                            <Button
                                type="button"
                                size="icon"
                                variant="outline"
                                onClick={() => load(page)}
                                disabled={isLoading}
                                aria-label="Refresh enquiries"
                                title="Refresh enquiries"
                                className="h-11 w-11 shrink-0 rounded-xl border-white/20 bg-white/10 text-white backdrop-blur-sm hover:bg-white/20 hover:text-white"
                            >
                                <RefreshCw
                                    className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
                                />
                            </Button>
                        </div>

                        <div className="grid grid-cols-3 gap-2.5 sm:gap-3">
                            {stats.map(({ label, value, icon: Icon, highlight }) => (
                                <div
                                    key={label}
                                    className={`rounded-2xl border p-3 backdrop-blur-md sm:p-4 ${
                                        highlight && value > 0
                                            ? "border-coral/40 bg-coral/15"
                                            : "border-white/10 bg-white/[0.07]"
                                    }`}
                                >
                                    <Icon
                                        className={`h-4 w-4 ${
                                            highlight ? "text-coral" : "text-white/60"
                                        }`}
                                    />
                                    <p className="mt-2 font-display text-2xl font-semibold tabular-nums sm:text-3xl">
                                        {isLoading ? "–" : value}
                                    </p>
                                    <p className="mt-0.5 text-[10px] leading-tight text-white/60 sm:text-xs">
                                        {label}
                                    </p>
                                </div>
                            ))}
                        </div>
                    </div>
                </section>

                {/* Attention banner */}
                {!isLoading && firstQuoted && (
                    <div
                        className={`flex flex-col gap-3 rounded-2xl border border-coral/25 bg-gradient-to-r from-coral/[0.09] to-transparent p-4 sm:flex-row sm:items-center ${ENTER}`}
                    >
                        <div className="flex min-w-0 flex-1 items-start gap-3">
                            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-coral/10 text-coral">
                                <Sparkles className="h-4 w-4" />
                            </span>

                            <div className="min-w-0">
                                <p className="text-sm font-semibold text-foreground">
                                    You have a quote waiting for you
                                </p>
                                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                                    Review the details and decide whether to
                                    proceed.
                                </p>
                            </div>
                        </div>

                        <Button
                            type="button"
                            variant="accent"
                            onClick={() => openDetail(firstQuoted.id)}
                            className="h-10 w-full rounded-xl sm:w-auto"
                        >
                            Review quote
                            <ArrowRight className="h-4 w-4" />
                        </Button>
                    </div>
                )}

                {/* List + filters */}
                <section className="space-y-4">
                    <div className="space-y-3">
                        <div>
                            <h2 className="font-display text-xl font-semibold tracking-tight sm:text-2xl">
                                Your safari requests
                            </h2>
                            <p className="mt-1 text-xs leading-5 text-muted-foreground sm:text-sm">
                                Select an enquiry to see its progress and
                                quotation details.
                            </p>
                        </div>

                        <FilterChips
                            value={statusFilter}
                            onChange={setStatusFilter}
                        />
                    </div>

                    {isLoading ? (
                        <div className="space-y-3">
                            {Array.from({ length: 4 }).map((_, i) => (
                                <Skeleton
                                    key={i}
                                    className="h-28 w-full rounded-2xl"
                                />
                            ))}
                        </div>
                    ) : loadError ? (
                        <Card className="rounded-3xl border-destructive/20 bg-destructive/[0.02]">
                            <CardContent className="flex flex-col items-center px-5 py-12 text-center">
                                <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-destructive/10 text-destructive">
                                    <AlertTriangle className="h-6 w-6" />
                                </div>

                                <h3 className="mt-4 font-semibold">
                                    We couldn't load your enquiries
                                </h3>

                                <p className="mt-2 max-w-sm text-sm leading-6 text-muted-foreground">
                                    {loadError}
                                </p>

                                <Button
                                    type="button"
                                    variant="outline"
                                    className="mt-5 h-10 rounded-xl"
                                    onClick={() => load(page)}
                                >
                                    <RefreshCw className="h-4 w-4" />
                                    Try again
                                </Button>
                            </CardContent>
                        </Card>
                    ) : enquiries.length === 0 ? (
                        <Card className="rounded-3xl border-dashed border-border/80 bg-muted/10 shadow-none">
                            <CardContent className="px-4 py-10 sm:px-6 sm:py-14">
                                <EmptyState
                                    icon={Inbox}
                                    title={
                                        statusFilter === "ALL"
                                            ? "Your safari journey starts here"
                                            : "No matching enquiries"
                                    }
                                    description={
                                        statusFilter === "ALL"
                                            ? "You haven't sent an enquiry yet. Explore our safari experiences and let our team help plan your next adventure."
                                            : "There are no enquiries with this status. Try selecting another filter."
                                    }
                                />
                            </CardContent>
                        </Card>
                    ) : (
                        <div className="space-y-3">
                            {enquiries.map((enquiry, index) => (
                                <EnquiryCard
                                    key={enquiry.id}
                                    enquiry={enquiry}
                                    index={index}
                                    onOpen={openDetail}
                                />
                            ))}
                        </div>
                    )}
                </section>

                {/* Pagination */}
                {!isLoading && !loadError && totalPages > 1 && (
                    <nav
                        aria-label="Pagination"
                        className="flex flex-col gap-3 border-t border-border/60 pt-5 sm:flex-row sm:items-center sm:justify-between"
                    >
                        <p className="text-center text-xs text-muted-foreground sm:text-left">
                            Page{" "}
                            <span className="font-semibold text-foreground">
                                {page + 1}
                            </span>{" "}
                            of{" "}
                            <span className="font-semibold text-foreground">
                                {totalPages}
                            </span>
                        </p>

                        <div className="grid grid-cols-2 gap-2 sm:flex">
                            <Button
                                type="button"
                                variant="outline"
                                className="h-10 rounded-xl"
                                onClick={() => load(page - 1)}
                                disabled={page === 0 || isLoading}
                            >
                                <ArrowLeft className="h-3.5 w-3.5" />
                                Previous
                            </Button>

                            <Button
                                type="button"
                                variant="outline"
                                className="h-10 rounded-xl"
                                onClick={() => load(page + 1)}
                                disabled={page + 1 >= totalPages || isLoading}
                            >
                                Next
                                <ArrowRight className="h-3.5 w-3.5" />
                            </Button>
                        </div>
                    </nav>
                )}

                <SupportCard
                    title="Need help planning your trip?"
                    text="Talk to our team for assistance with your safari."
                />
            </div>
        </PageShell>
    );
}