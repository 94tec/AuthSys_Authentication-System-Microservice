"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
    AlertTriangle,
    ArrowRight,
    CalendarClock,
    CalendarDays,
    CheckCircle2,
    ChevronLeft,
    ChevronRight,
    Clock,
    FileText,
    Inbox,
    Mail,
    MessageCircle,
    Phone,
    PlaneTakeoff,
    Plus,
    RefreshCw,
    Search,
    Send,
    Sparkles,
    UserCheck,
    UserPlus,
    Users,
    Wallet,
    XCircle,
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

import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";

import { tourAdminApi } from "@/lib/tour-admin-api";
import { enquiryApi } from "@/lib/enquiry-api";
import { userApi, type StaffUser } from "@/lib/user-api";

import {
    ENQUIRY_STATUS_TRANSITIONS,
    type EnquiryDashboardSummary,
    type EnquiryDetailResponse,
    type EnquirySummaryResponse,
    type TourEnquiryStatus,
} from "@/types/enquiry-types";

import type { ApiError } from "@/types/index-types";

/* ============================================================
   CONSTANTS
============================================================ */

const PAGE_SIZE = 20;

const STATUSES: TourEnquiryStatus[] = [
    "NEW", "CONTACTED", "QUOTED", "CONVERTED", "COMPLETED", "LOST", "ARCHIVED",
];

const STATUS_LABELS: Record<TourEnquiryStatus, string> = {
    NEW: "New",
    CONTACTED: "Contacted",
    QUOTED: "Quoted",
    CONVERTED: "Converted",
    COMPLETED: "Completed",
    LOST: "Lost",
    ARCHIVED: "Archived",
};

const STATUS_ICONS: Record<TourEnquiryStatus, React.ElementType> = {
    NEW: Inbox,
    CONTACTED: UserCheck,
    QUOTED: Send,
    CONVERTED: Sparkles,
    COMPLETED: CheckCircle2,
    LOST: XCircle,
    ARCHIVED: FileText,
};

const STATUS_STYLES: Record<TourEnquiryStatus, string> = {
    NEW: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-400",
    CONTACTED: "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/30 dark:text-blue-400",
    QUOTED: "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-900 dark:bg-violet-950/30 dark:text-violet-400",
    CONVERTED: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-400",
    COMPLETED: "border-teal-200 bg-teal-50 text-teal-700 dark:border-teal-900 dark:bg-teal-950/30 dark:text-teal-400",
    LOST: "border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-400",
    ARCHIVED: "border-muted-foreground/20 bg-muted text-muted-foreground",
};

const CONTACT_ICON = {
    EMAIL: Mail,
    PHONE: Phone,
    WHATSAPP: MessageCircle,
} as const;

type QueueKey = "all" | "unassigned" | "overdue" | "departures";

const QUEUE_TABS: { key: QueueKey; label: string; icon: React.ElementType }[] = [
    { key: "all", label: "All enquiries", icon: Inbox },
    { key: "unassigned", label: "Unassigned", icon: UserPlus },
    { key: "overdue", label: "Overdue follow-up", icon: Clock },
    { key: "departures", label: "Departing soon", icon: PlaneTakeoff },
];

/* ============================================================
   HELPERS
============================================================ */

function formatDate(iso?: string) {
    if (!iso) return "—";
    return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function formatDateTime(iso: string) {
    return new Date(iso).toLocaleString(undefined, {
        day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
    });
}

function getGroupSize(e: { groupSizeAdults?: number; groupSizeChildren?: number }) {
    return (e.groupSizeAdults ?? 0) + (e.groupSizeChildren ?? 0);
}

function getStatusLabel(status: TourEnquiryStatus) {
    return STATUS_LABELS[status] ?? status;
}

function getApiErrorMessage(err: unknown, fallback: string) {
    return (err as ApiError)?.message || fallback;
}

/* ============================================================
   STATUS BADGE
============================================================ */

function EnquiryStatusBadge({ status }: { status: TourEnquiryStatus }) {
    const Icon = STATUS_ICONS[status];
    return (
        <Badge variant="outline" className={`rounded-full px-2.5 py-1 text-[10px] font-semibold ${STATUS_STYLES[status]}`}>
            <Icon className="mr-1 h-3 w-3" />
            {getStatusLabel(status)}
        </Badge>
    );
}

/* ============================================================
   METRIC CARD
============================================================ */

function EnquiryMetric({
                           label, value, icon: Icon, className = "",
                       }: {
    label: string;
    value: number;
    icon: React.ElementType;
    className?: string;
}) {
    return (
        <Card className={className}>
            <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3">
                    <div>
                        <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                            {label}
                        </p>
                        <p className="mt-1 font-display text-2xl font-semibold tracking-tight">{value}</p>
                    </div>
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                        <Icon className="h-4 w-4" />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}

/* ============================================================
   PAGE
============================================================ */

export default function AdminEnquiriesPage() {
    /* ---------------- LIST STATE ---------------- */
    const [enquiries, setEnquiries] = useState<EnquirySummaryResponse[]>([]);
    const [page, setPage] = useState(0);
    const [totalPages, setTotalPages] = useState(0);
    const [totalElements, setTotalElements] = useState(0);
    const [isLoading, setIsLoading] = useState(true);
    const [loadError, setLoadError] = useState<string | null>(null);

    /* ---------------- FILTERS ---------------- */
    const [statusFilter, setStatusFilter] = useState<TourEnquiryStatus | "ALL">("ALL");
    const [search, setSearch] = useState("");
    const [activeQueue, setActiveQueue] = useState<QueueKey>("all");

    /* ---------------- DASHBOARD METRICS ---------------- */
    const [summary, setSummary] = useState<EnquiryDashboardSummary | null>(null);

    /* ---------------- DETAIL STATE ---------------- */
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [detail, setDetail] = useState<EnquiryDetailResponse | null>(null);
    const [detailLoading, setDetailLoading] = useState(false);
    const [statusDraft, setStatusDraft] = useState<TourEnquiryStatus>("NEW");
    const [statusNote, setStatusNote] = useState("");
    const [isSavingStatus, setIsSavingStatus] = useState(false);

    const [noteDraft, setNoteDraft] = useState("");
    const [isSavingNote, setIsSavingNote] = useState(false);

    const [assignDraft, setAssignDraft] = useState("");
    const [isAssigning, setIsAssigning] = useState(false);

    //
    const [staffUsers, setStaffUsers] = useState<StaffUser[]>([]);
    const [staffLoading, setStaffLoading] = useState(false);

    /* ---------------- QUOTE FORM STATE ---------------- */
    const [showQuoteForm, setShowQuoteForm] = useState(false);
    const [quotePricePerAdult, setQuotePricePerAdult] = useState("");
    const [quotePricePerChild, setQuotePricePerChild] = useState("");
    const [quoteTotalPrice, setQuoteTotalPrice] = useState("");
    const [quoteCurrency, setQuoteCurrency] = useState("KES");
    const [quoteValidUntil, setQuoteValidUntil] = useState("");
    const [quoteInclusions, setQuoteInclusions] = useState("");
    const [isSavingQuote, setIsSavingQuote] = useState(false);
    const [sendingQuoteId, setSendingQuoteId] = useState<string | null>(null);
    const [quoteTotalManuallyEdited, setQuoteTotalManuallyEdited] = useState(false);

    /* =========================================================
       LOAD LIST (respects active queue tab + filters)
    ========================================================= */

    const load = useCallback(async (targetPage = 0) => {
        setIsLoading(true);
        setLoadError(null);

        try {
            let data;
            if (activeQueue === "unassigned") {
                data = await enquiryApi.adminUnassignedQueue(targetPage, PAGE_SIZE);
            } else if (activeQueue === "overdue") {
                data = await enquiryApi.adminOverdueFollowUpQueue(targetPage, PAGE_SIZE);
            } else if (activeQueue === "departures") {
                data = await enquiryApi.adminUpcomingDeparturesQueue(14, targetPage, PAGE_SIZE);
            } else {
                data = await enquiryApi.adminSearch({
                    page: targetPage,
                    size: PAGE_SIZE,
                    status: statusFilter === "ALL" ? undefined : statusFilter,
                    search: search.trim() || undefined,
                });
            }

            setEnquiries(Array.isArray(data?.content) ? data.content : []);
            setTotalPages(data?.totalPages ?? 0);
            setTotalElements(data?.totalElements ?? 0);
            setPage(targetPage);
        } catch (err) {
            console.error(err);
            const message = getApiErrorMessage(err, "Couldn't load enquiries.");
            setLoadError(message);
            setEnquiries([]);
            toast.error(message);
        } finally {
            setIsLoading(false);
        }
    }, [activeQueue, statusFilter, search]);

    useEffect(() => { load(0); }, [load]);

    const loadSummary = useCallback(async () => {
        try {
            const data = await enquiryApi.adminDashboardSummary();
            setSummary(data);
        } catch (err) {
            console.error(err);
            // Metrics are a nice-to-have — fail quietly, don't block the list.
        }
    }, []);

    useEffect(() => { loadSummary(); }, [loadSummary]);

    useEffect(() => {
        if (!showQuoteForm || quoteTotalManuallyEdited || !detail) return;

        const adults = detail.groupSizeAdults ?? 0;
        const children = detail.groupSizeChildren ?? 0;
        const perAdult = Number(quotePricePerAdult) || 0;
        const perChild = Number(quotePricePerChild) || 0;

        const total = perAdult * adults + perChild * children;
        setQuoteTotalPrice(total > 0 ? String(total) : "");
    }, [quotePricePerAdult, quotePricePerChild, detail, showQuoteForm, quoteTotalManuallyEdited]);

    useEffect(() => {
        if (!selectedId) return;
        setStaffLoading(true);
        userApi.listStaff()
            .then(setStaffUsers)
            .catch((err) => {
                console.error(err);
                // Non-fatal — the assign dropdown just shows empty/loading state.
            })
            .finally(() => setStaffLoading(false));
    }, [selectedId]);

    /* =========================================================
       OPEN DETAIL
    ========================================================= */

    const openDetail = useCallback(async (id: string) => {
        setSelectedId(id);
        setDetailLoading(true);
        setDetail(null);
        setShowQuoteForm(false);

        try {
            const data = await enquiryApi.adminGetDetail(id);
            setDetail(data);
            setStatusDraft(data.status);
            setStatusNote("");
            setAssignDraft(data.assignedTo ?? "");
        } catch (err) {
            console.error(err);
            toast.error(getApiErrorMessage(err, "Couldn't load enquiry."));
            setSelectedId(null);
        } finally {
            setDetailLoading(false);
        }
    }, []);

    function closeDetail() {
        setSelectedId(null);
        setDetail(null);
    }

    async function refreshDetail() {
        if (!selectedId) return;
        const data = await enquiryApi.adminGetDetail(selectedId);
        setDetail(data);
        setStatusDraft(data.status);
    }

    /* =========================================================
       STATUS CHANGE
    ========================================================= */

    const allowedNextStatuses = useMemo(() => {
        if (!detail) return [];
        return ENQUIRY_STATUS_TRANSITIONS[detail.status] ?? [];
    }, [detail]);

    async function handleStatusSave() {
        if (!selectedId || !detail) return;
        if (statusDraft === detail.status) {
            toast.error("Choose a different status to update.");
            return;
        }

        setIsSavingStatus(true);
        try {
            const updated = await enquiryApi.adminUpdateStatus(selectedId, {
                status: statusDraft,
                note: statusNote.trim() || undefined,
            });
            setDetail(updated);
            setStatusNote("");
            setEnquiries((prev) => prev.map((item) =>
                item.id === updated.id ? { ...item, status: updated.status } : item,
            ));
            toast.success(`Marked as ${getStatusLabel(updated.status)}`);
            loadSummary();
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't update status."));
            setStatusDraft(detail.status);
        } finally {
            setIsSavingStatus(false);
        }
    }

    /* =========================================================
       ASSIGN
    ========================================================= */

    async function handleAssign() {
        if (!selectedId || !assignDraft.trim()) {
            toast.error("Enter a staff ID to assign.");
            return;
        }

        setIsAssigning(true);
        try {
            await enquiryApi.adminAssign(selectedId, { staffId: assignDraft.trim() });
            await refreshDetail();
            setEnquiries((prev) => prev.map((item) =>
                item.id === selectedId ? { ...item, assignedTo: assignDraft.trim() } : item,
            ));
            toast.success("Enquiry assigned");
            loadSummary();
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't assign enquiry."));
        } finally {
            setIsAssigning(false);
        }
    }

    /* =========================================================
       NOTES
    ========================================================= */

    async function handleAddNote() {
        if (!selectedId || !noteDraft.trim()) {
            toast.error("Write a note first.");
            return;
        }

        setIsSavingNote(true);
        try {
            await enquiryApi.adminAddNote(selectedId, noteDraft.trim());
            setNoteDraft("");
            await refreshDetail();
            toast.success("Note added");
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't add note."));
        } finally {
            setIsSavingNote(false);
        }
    }

    /* =========================================================
       QUOTES
    ========================================================= */
    async function openQuoteForm() {
        setShowQuoteForm(true);
        if (!detail) return;

        try {
            // ⚠️ Assumes EnquiryDetailResponse exposes tourId. Confirm against the
            // real type — if it's missing, this fetch has nothing to key off and
            // needs the field added to the backend DTO first.
            const tour = await tourAdminApi.getTour(detail.tourId);

            setQuoteCurrency(tour.currency);
            setQuotePricePerAdult(String(tour.price));
            // ⚠️ TourDetail has no distinct child price — defaulting to the same
            // adult price. Both fields stay fully editable below.
            setQuotePricePerChild(String(tour.price));
            setQuoteTotalManuallyEdited(false);
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't load tour pricing — enter manually."));
        }
    }

    function resetQuoteForm() {
        setQuotePricePerAdult("");
        setQuotePricePerChild("");
        setQuoteTotalPrice("");
        setQuoteCurrency("KES");
        setQuoteValidUntil("");
        setQuoteInclusions("");
        setQuoteTotalManuallyEdited(false);
    }

    async function handleCreateQuote() {
        if (!selectedId) return;

        const pricePerAdult = Number(quotePricePerAdult);
        const totalPrice = Number(quoteTotalPrice);

        if (!pricePerAdult || pricePerAdult <= 0) {
            toast.error("Enter a valid price per adult.");
            return;
        }
        if (!totalPrice || totalPrice <= 0) {
            toast.error("Enter a valid total price.");
            return;
        }
        if (!quoteValidUntil) {
            toast.error("Set a valid-until date.");
            return;
        }

        setIsSavingQuote(true);
        try {
            await enquiryApi.adminCreateQuote(selectedId, {
                pricePerAdult,
                pricePerChild: quotePricePerChild ? Number(quotePricePerChild) : undefined,
                totalPrice,
                currency: quoteCurrency,
                validUntil: quoteValidUntil,
                inclusionsNote: quoteInclusions.trim() || undefined,
                adultCount: detail?.groupSizeAdults ?? 0,
                childCount: detail?.groupSizeChildren ?? 0,
            });
            resetQuoteForm();
            setShowQuoteForm(false);
            await refreshDetail();
            toast.success("Quote drafted");
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't create quote."));
        } finally {
            setIsSavingQuote(false);
        }
    }

    async function handleDownloadQuotePdf(quoteId: string) {
        try {
            const blob = await enquiryApi.downloadQuotePdf(selectedId!, quoteId, true);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `quote-${quoteId}.pdf`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (err) {
            toast.error(getApiErrorMessage(err, "Couldn't download quote PDF."));
        }
    }

    async function handleSendQuote(quoteId: string) {
        if (!selectedId) return;
        setSendingQuoteId(quoteId);
        try {
            await enquiryApi.adminSendQuote(selectedId, quoteId);
            await refreshDetail();
            setEnquiries((prev) => prev.map((item) =>
                item.id === selectedId ? { ...item, status: "QUOTED" } : item,
            ));
            toast.success("Quote sent to customer");
            loadSummary();
        } catch (err) {
            const apiErr = err as ApiError & { code?: string; currentStatus?: string };

            if (apiErr?.code === "QUOTE_STATUS_CONFLICT") {
                // The quote already sent successfully in an earlier attempt —
                // our local state was just stale. Resync rather than showing
                // a scary error for something that isn't actually broken.
                await refreshDetail();
                toast.info("This quote was already sent.");
            } else {
                toast.error(getApiErrorMessage(err, "Couldn't send quote."));
            }
        } finally {
            setSendingQuoteId(null);
        }
    }

    /* =========================================================
       RENDER
    ========================================================= */

    return (
        <div className="space-y-7 pb-10">
            {/* HEADER */}
            <PageHeader
                eyebrow="Tour Operations"
                title="Customer enquiries"
                subtitle={
                    isLoading
                        ? "Loading enquiries…"
                        : loadError
                            ? "Unable to load enquiries"
                            : `${totalElements} ${totalElements === 1 ? "enquiry" : "enquiries"} in view`
                }
                action={
                    <Button variant="outline" size="sm" onClick={() => { load(page); loadSummary(); }} disabled={isLoading}>
                        <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} />
                        Refresh
                    </Button>
                }
            />

            {/* PIPELINE METRICS */}
            {summary && (
                <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
                    <EnquiryMetric label="New" value={summary.newCount} icon={Inbox} className="border-amber-200/60 dark:border-amber-900/50" />
                    <EnquiryMetric label="Contacted" value={summary.contactedCount} icon={UserCheck} />
                    <EnquiryMetric label="Quoted" value={summary.quotedCount} icon={Send} />
                    <EnquiryMetric label="Converted" value={summary.convertedCount} icon={Sparkles} className="border-emerald-200/60 dark:border-emerald-900/50" />
                    <EnquiryMetric label="Completed" value={summary.completedCount} icon={CheckCircle2} />
                    <EnquiryMetric label="Lost" value={summary.lostCount} icon={XCircle} />
                    <EnquiryMetric label="Unassigned" value={summary.unassignedCount} icon={UserPlus} className="border-red-200/60 dark:border-red-900/50" />
                </div>
            )}

            {/* QUEUE TABS */}
            <div className="flex flex-wrap gap-2">
                {QUEUE_TABS.map(({ key, label, icon: Icon }) => (
                    <button
                        key={key}
                        type="button"
                        onClick={() => setActiveQueue(key)}
                        className={`
                            inline-flex items-center gap-1.5 rounded-full border px-3.5 py-2 text-xs font-medium transition-colors
                            ${activeQueue === key
                            ? "border-primary/30 bg-primary/10 text-primary"
                            : "border-border bg-background text-muted-foreground hover:bg-muted"}
                        `}
                    >
                        <Icon className="h-3.5 w-3.5" />
                        {label}
                        {key === "unassigned" && summary ? (
                            <span className="ml-1 rounded-full bg-muted px-1.5 text-[10px] font-semibold">{summary.unassignedCount}</span>
                        ) : null}
                        {key === "overdue" && summary ? (
                            <span className="ml-1 rounded-full bg-muted px-1.5 text-[10px] font-semibold">{summary.overdueFollowUpCount}</span>
                        ) : null}
                        {key === "departures" && summary ? (
                            <span className="ml-1 rounded-full bg-muted px-1.5 text-[10px] font-semibold">{summary.upcomingDeparturesCount}</span>
                        ) : null}
                    </button>
                ))}
            </div>

            {/* FILTER BAR — only relevant for the "all" queue */}
            {activeQueue === "all" && (
                <Card>
                    <CardContent className="p-3">
                        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
                            <div className="relative flex-1">
                                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                                <Input
                                    value={search}
                                    onChange={(e) => setSearch(e.target.value)}
                                    onKeyDown={(e) => { if (e.key === "Enter") load(0); }}
                                    placeholder="Search name or email…"
                                    className="border-none bg-muted/50 pl-9 shadow-none"
                                />
                            </div>

                            <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as TourEnquiryStatus | "ALL")}>
                                <SelectTrigger className="w-full border-none bg-muted/50 shadow-none lg:w-48">
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="ALL">All statuses</SelectItem>
                                    {STATUSES.map((s) => (
                                        <SelectItem key={s} value={s}>{getStatusLabel(s)}</SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>

                            <Button size="sm" onClick={() => load(0)} disabled={isLoading}>Apply</Button>
                        </div>
                    </CardContent>
                </Card>
            )}

            {/* TABLE */}
            {isLoading ? (
                <div className="space-y-2">
                    {Array.from({ length: 7 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-xl" />)}
                </div>
            ) : loadError ? (
                <EmptyState icon={AlertTriangle} title="Couldn't load enquiries" description={loadError} />
            ) : enquiries.length === 0 ? (
                <EmptyState
                    icon={Inbox}
                    title={activeQueue === "all" ? "No enquiries" : "Nothing here"}
                    description={activeQueue === "all" ? "New customer enquiries will appear here." : "This queue is currently empty."}
                />
            ) : (
                <>
                    <div className="hidden overflow-hidden rounded-xl border border-border bg-card shadow-sm lg:block">
                        <Table>
                            <TableHeader>
                                <TableRow className="hover:bg-transparent">
                                    <TableHead>Customer</TableHead>
                                    <TableHead>Tour</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Assigned</TableHead>
                                    <TableHead>Received</TableHead>
                                    <TableHead className="w-10" />
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {enquiries.map((enquiry) => (
                                    <TableRow key={enquiry.id} className="group cursor-pointer" onClick={() => openDetail(enquiry.id)}>
                                        <TableCell>
                                            <div className="flex items-center gap-3">
                                                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-muted">
                                                    <Mail className="h-4 w-4 text-muted-foreground" />
                                                </div>
                                                <div className="min-w-0">
                                                    <div className="flex items-center gap-2">
                                                        <p className="max-w-[180px] truncate font-medium">{enquiry.fullName}</p>
                                                        {enquiry.status === "NEW" && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-amber-500" />}
                                                    </div>
                                                    <p className="max-w-[220px] truncate text-xs text-muted-foreground">{enquiry.email}</p>
                                                </div>
                                            </div>
                                        </TableCell>
                                        <TableCell>
                                            <p className="max-w-[190px] truncate text-sm font-medium">{enquiry.tourName}</p>
                                        </TableCell>
                                        <TableCell><EnquiryStatusBadge status={enquiry.status} /></TableCell>
                                        <TableCell className="text-xs text-muted-foreground">
                                            {enquiry.assignedTo ? enquiry.assignedTo.slice(0, 10) + "…" : "—"}
                                        </TableCell>
                                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                                            {formatDate(enquiry.createdDate)}
                                        </TableCell>
                                        <TableCell>
                                            <ArrowRight className="h-4 w-4 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-primary" />
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </div>

                    {/* MOBILE CARDS */}
                    <div className="grid gap-3 lg:hidden">
                        {enquiries.map((enquiry) => (
                            <Card key={enquiry.id} className="cursor-pointer transition-all hover:border-primary/30" onClick={() => openDetail(enquiry.id)}>
                                <CardContent className="p-4">
                                    <div className="flex items-start justify-between gap-3">
                                        <div className="min-w-0">
                                            <p className="truncate font-medium">{enquiry.fullName}</p>
                                            <p className="truncate text-xs text-muted-foreground">{enquiry.email}</p>
                                        </div>
                                        <EnquiryStatusBadge status={enquiry.status} />
                                    </div>
                                    <Separator className="my-3" />
                                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                                        <span className="truncate">{enquiry.tourName}</span>
                                        <span>{formatDate(enquiry.createdDate)}</span>
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>

                    {totalPages > 1 && (
                        <div className="flex flex-col gap-3 pt-2 sm:flex-row sm:items-center sm:justify-between">
                            <span className="text-xs text-muted-foreground">
                                Showing <strong className="font-medium text-foreground">{page * PAGE_SIZE + 1}</strong>
                                {" – "}
                                <strong className="font-medium text-foreground">{Math.min((page + 1) * PAGE_SIZE, totalElements)}</strong>
                                {" of "}{totalElements}
                            </span>
                            <div className="flex gap-2">
                                <Button variant="outline" size="sm" onClick={() => load(page - 1)} disabled={page === 0 || isLoading}>
                                    <ChevronLeft className="h-3.5 w-3.5" /> Previous
                                </Button>
                                <Button variant="outline" size="sm" onClick={() => load(page + 1)} disabled={page + 1 >= totalPages || isLoading}>
                                    Next <ChevronRight className="h-3.5 w-3.5" />
                                </Button>
                            </div>
                        </div>
                    )}
                </>
            )}

            {/* DETAIL SHEET */}
            <Sheet open={!!selectedId} onOpenChange={(open) => !open && closeDetail()}>
                <SheetContent
                    className="
                        w-full
                        overflow-hidden
                        p-0
                        sm:max-w-2xl
                    "
                >
                    {detailLoading ? (
                        <div className="space-y-4 p-6">
                            <Skeleton className="h-24 w-full rounded-2xl" />
                            <Skeleton className="h-28 w-full rounded-2xl" />
                            <Skeleton className="h-40 w-full rounded-2xl" />
                            <Skeleton className="h-32 w-full rounded-2xl" />
                        </div>
                    ) : detail ? (
                        <div className="flex h-full min-h-0 flex-col">

                            {/* =========================================
                             * HEADER
                             * ========================================= */}
                            <div
                                className="
                                    shrink-0
                                    border-b
                                    border-border/70
                                    bg-background/95
                                    px-5
                                    py-5
                                    backdrop-blur-xl
                                    sm:px-6
                                "
                            >
                                <div className="flex items-start gap-4">

                                    {/* Avatar */}
                                    <div
                                        className="
                                            flex
                                            h-12
                                            w-12
                                            shrink-0
                                            items-center
                                            justify-center
                                            rounded-2xl
                                            bg-accent/10
                                            text-lg
                                            font-semibold
                                            text-accent
                                            ring-1
                                            ring-accent/20
                                        "
                                    >
                                        {detail.fullName
                                            ?.trim()
                                            ?.charAt(0)
                                            ?.toUpperCase() ?? "?"}
                                    </div>

                                    <div className="min-w-0 flex-1">
                                        <div className="flex flex-wrap items-center gap-2">
                                            <SheetTitle
                                                className="
                                                    min-w-0
                                                    truncate
                                                    font-display
                                                    text-xl
                                                    font-semibold
                                                    tracking-tight
                                                "
                                            >
                                                {detail.fullName}
                                            </SheetTitle>

                                            <EnquiryStatusBadge
                                                status={detail.status}
                                            />
                                        </div>

                                        <SheetDescription
                                            className="
                                                mt-1.5
                                                truncate
                                                text-sm
                                            "
                                        >
                                            {detail.email}
                                            {detail.phone && (
                                                <>
                                    <span className="mx-1.5 text-border">
                                        •
                                    </span>
                                                    {detail.phone}
                                                </>
                                            )}
                                        </SheetDescription>
                                    </div>
                                </div>

                                {/* Contact actions */}
                                <div className="mt-4 grid grid-cols-3 gap-2">
                                    <Button
                                        variant="outline"
                                        size="sm"
                                        className="h-9 rounded-xl"
                                        asChild
                                    >
                                        <a href={`mailto:${detail.email}`}>
                                            <Mail className="mr-1.5 h-3.5 w-3.5" />
                                            Email
                                        </a>
                                    </Button>

                                    {detail.phone ? (
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            className="h-9 rounded-xl"
                                            asChild
                                        >
                                            <a href={`tel:${detail.phone}`}>
                                                <Phone className="mr-1.5 h-3.5 w-3.5" />
                                                Call
                                            </a>
                                        </Button>
                                    ) : (
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            disabled
                                            className="h-9 rounded-xl"
                                        >
                                            <Phone className="mr-1.5 h-3.5 w-3.5" />
                                            Call
                                        </Button>
                                    )}

                                    {detail.phone ? (
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            className="h-9 rounded-xl"
                                            asChild
                                        >
                                            <a
                                                href={`https://wa.me/${detail.phone.replace(/\D/g, "")}`}
                                                target="_blank"
                                                rel="noreferrer"
                                            >
                                                <MessageCircle className="mr-1.5 h-3.5 w-3.5" />
                                                WhatsApp
                                            </a>
                                        </Button>
                                    ) : (
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            disabled
                                            className="h-9 rounded-xl"
                                        >
                                            <MessageCircle className="mr-1.5 h-3.5 w-3.5" />
                                            WhatsApp
                                        </Button>
                                    )}
                                </div>
                            </div>

                            {/* =========================================
                             * SCROLLABLE WORKSPACE
                             * ========================================= */}
                            <div
                                className="
                                    min-h-0
                                    flex-1
                                    overflow-y-auto
                                    overscroll-contain
                                    px-5
                                    py-6
                                    sm:px-6
                                "
                            >
                                <div className="space-y-6">

                                    {/* =================================
                                     * TRIP OVERVIEW
                                     * ================================= */}
                                    <section>
                                        <div className="mb-3 flex items-center justify-between">
                                            <div>
                                                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                                                    Trip overview
                                                </p>

                                                <h3 className="mt-1 font-display text-base font-semibold">
                                                    {detail.tourName}
                                                </h3>
                                            </div>
                                        </div>

                                        <div
                                            className="
                                                overflow-hidden
                                                rounded-2xl
                                                border
                                                border-border/70
                                                bg-card
                                                shadow-sm
                                            "
                                        >
                                            <div className="grid grid-cols-2 divide-x divide-y divide-border/70 sm:grid-cols-3">

                                                <div className="p-4">
                                                    <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                                                        Travel date
                                                    </p>

                                                    <p className="mt-1.5 text-sm font-semibold">
                                                        {formatDate(detail.preferredDate)}
                                                    </p>

                                                    {detail.flexibleDates && (
                                                        <span className="mt-1 inline-flex text-[10px] font-medium text-primary">
                                                            Flexible dates
                                                        </span>
                                                    )}
                                                </div>

                                                <div className="p-4">
                                                    <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                                                        Travellers
                                                    </p>

                                                    <p className="mt-1.5 inline-flex items-center gap-1.5 text-sm font-semibold">
                                                        <Users className="h-3.5 w-3.5 text-muted-foreground" />
                                                        {(detail.groupSizeAdults ?? 0) +
                                                            (detail.groupSizeChildren ?? 0)}
                                                    </p>

                                                    <p className="mt-1 text-[10px] text-muted-foreground">
                                                        {detail.groupSizeAdults ?? 0} adults
                                                        {detail.groupSizeChildren
                                                            ? ` · ${detail.groupSizeChildren} children`
                                                            : ""}
                                                    </p>
                                                </div>

                                                {detail.budgetRange && (
                                                    <div className="p-4">
                                                        <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                                                            Budget
                                                        </p>

                                                        <p className="mt-1.5 inline-flex items-center gap-1.5 text-sm font-semibold">
                                                            <Wallet className="h-3.5 w-3.5 text-muted-foreground" />
                                                            {detail.budgetRange}
                                                        </p>
                                                    </div>
                                                )}

                                                {detail.preferredContact && (
                                                    <div className="p-4">
                                                        <p className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                                                            Contact
                                                        </p>

                                                        <p className="mt-1.5 text-sm font-semibold">
                                                            {detail.preferredContact}
                                                        </p>
                                                    </div>
                                                )}

                                            </div>
                                        </div>
                                    </section>

                                    {/* =================================
                                     * CUSTOMER MESSAGE
                                     * ================================= */}
                                    {detail.requirements && (
                                        <section>
                                            <div className="mb-3">
                                                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                                                    Customer message
                                                </p>
                                            </div>

                                            <div
                                                className="
                                                    relative
                                                    overflow-hidden
                                                    rounded-2xl
                                                    border
                                                    border-accent/15
                                                    bg-accent/[0.035]
                                                    p-5
                                                "
                                            >
                                                <div
                                                    aria-hidden="true"
                                                    className="
                                                        absolute
                                                        left-0
                                                        top-0
                                                        h-full
                                                        w-1
                                                        bg-accent/60
                                                    "
                                                />

                                                <p className="whitespace-pre-wrap text-sm leading-7 text-foreground/90">
                                                    {detail.requirements}
                                                </p>
                                            </div>
                                        </section>
                                    )}

                                    {/* =================================
                                     * STATUS + ASSIGNMENT
                                     * ================================= */}
                                    <section className="grid gap-4 sm:grid-cols-2">

                                        {/* Status */}
                                        <div className="rounded-2xl border border-border/70 bg-card p-4 shadow-sm">
                                            <div className="mb-3">
                                                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                                                    Status
                                                </p>

                                                <p className="mt-1 text-sm text-muted-foreground">
                                                    Move this enquiry through its workflow.
                                                </p>
                                            </div>

                                            {allowedNextStatuses.length === 0 ? (
                                                <div className="rounded-xl bg-muted/50 p-3">
                                                    <p className="text-xs leading-5 text-muted-foreground">
                                                        This enquiry is in a final state.
                                                    </p>
                                                </div>
                                            ) : (
                                                <div className="space-y-3">
                                                    <Select
                                                        value={statusDraft}
                                                        onValueChange={(v) =>
                                                            setStatusDraft(
                                                                v as TourEnquiryStatus,
                                                            )
                                                        }
                                                    >
                                                        <SelectTrigger className="rounded-xl">
                                                            <SelectValue />
                                                        </SelectTrigger>

                                                        <SelectContent>
                                                            <SelectItem
                                                                value={detail.status}
                                                            >
                                                                {getStatusLabel(
                                                                    detail.status,
                                                                )}{" "}
                                                                (current)
                                                            </SelectItem>

                                                            {allowedNextStatuses.map((s) => (
                                                                <SelectItem
                                                                    key={s}
                                                                    value={s}
                                                                >
                                                                    {getStatusLabel(s)}
                                                                </SelectItem>
                                                            ))}
                                                        </SelectContent>
                                                    </Select>

                                                    <Textarea
                                                        rows={2}
                                                        value={statusNote}
                                                        onChange={(e) =>
                                                            setStatusNote(e.target.value)
                                                        }
                                                        placeholder="Optional note…"
                                                        className="resize-none rounded-xl"
                                                    />

                                                    <Button
                                                        onClick={handleStatusSave}
                                                        disabled={
                                                            isSavingStatus ||
                                                            statusDraft === detail.status
                                                        }
                                                        className="w-full rounded-xl"
                                                    >
                                                        {isSavingStatus
                                                            ? "Saving…"
                                                            : "Update status"}
                                                    </Button>
                                                </div>
                                            )}
                                        </div>

                                        {/* Assignment */}
                                        <div className="mt-3 flex gap-2">
                                            <Select
                                                value={assignDraft}
                                                onValueChange={setAssignDraft}
                                                disabled={staffLoading}
                                            >
                                                <SelectTrigger className="rounded-xl">
                                                    <SelectValue placeholder={staffLoading ? "Loading staff…" : "Select staff member"} />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    {staffUsers.map((user) => (
                                                        <SelectItem key={user.userId} value={user.userId}>
                                                            {user.fullName} <span className="text-muted-foreground">— {user.roles[0]}</span>
                                                        </SelectItem>
                                                    ))}
                                                </SelectContent>
                                            </Select>

                                            <Button
                                                variant="outline"
                                                onClick={handleAssign}
                                                disabled={isAssigning || !assignDraft}
                                                className="rounded-xl"
                                            >
                                                {isAssigning ? "Assigning…" : "Assign"}
                                            </Button>
                                        </div>
                                    </section>

                                    {/* =================================
                                     * QUOTES
                                     * ================================= */}
                                    <section>
                                        <div className="mb-3 flex items-center justify-between">
                                            <div>
                                                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                                                    Quotes
                                                </p>

                                                <p className="mt-1 text-sm text-muted-foreground">
                                                    Pricing proposals sent to the customer.
                                                </p>
                                            </div>

                                            {!showQuoteForm && (
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    className="rounded-xl"
                                                    onClick={openQuoteForm}
                                                >
                                                    <Plus className="mr-1.5 h-3.5 w-3.5" />
                                                    New quote
                                                </Button>
                                            )}
                                        </div>

                                        {detail.quotes.length === 0 &&
                                            !showQuoteForm && (
                                                <div className="rounded-2xl border border-dashed border-border p-6 text-center">
                                                    <Wallet className="mx-auto h-5 w-5 text-muted-foreground/50" />

                                                    <p className="mt-2 text-sm font-medium">
                                                        No quotes yet
                                                    </p>

                                                    <p className="mt-1 text-xs text-muted-foreground">
                                                        Create a quote when you're ready to
                                                        send pricing.
                                                    </p>
                                                </div>
                                            )}

                                        <div className="space-y-3">
                                            {detail.quotes.map((q) => (
                                                <div
                                                    key={q.id}
                                                    className="
                                                        rounded-2xl
                                                        border
                                                        border-border/70
                                                        bg-card
                                                        p-4
                                                        shadow-sm
                                                        transition-shadow
                                                        hover:shadow-md
                                                    "
                                                >
                                                    <div className="flex items-start justify-between gap-3">
                                                        <div>
                                                            <p className="text-lg font-semibold tracking-tight">
                                                                {q.currency}{" "}
                                                                {q.totalPrice.toLocaleString()}
                                                            </p>

                                                            <p className="mt-1 text-xs text-muted-foreground">
                                                                {q.currency}{" "}
                                                                {q.pricePerAdult.toLocaleString()}
                                                                /adult
                                                                {q.pricePerChild
                                                                    ? ` · ${q.currency} ${q.pricePerChild.toLocaleString()}/child`
                                                                    : ""}
                                                            </p>
                                                        </div>

                                                        <Badge
                                                            variant="outline"
                                                            className="shrink-0 rounded-full text-[10px]"
                                                        >
                                                            {q.status}
                                                        </Badge>
                                                    </div>

                                                    <div className="mt-3 flex items-center justify-between border-t border-border/60 pt-3">
                                                        <p className="text-xs text-muted-foreground">
                                                            Valid until{" "}
                                                            <span className="font-medium text-foreground">
                                                {formatDate(q.validUntil)}
                                            </span>
                                                        </p>
                                                    </div>

                                                    {q.inclusionsNote && (
                                                        <p className="mt-3 whitespace-pre-wrap rounded-xl bg-muted/40 p-3 text-xs leading-5 text-muted-foreground">
                                                            {q.inclusionsNote}
                                                        </p>
                                                    )}

                                                    {q.status === "DRAFT" && (
                                                        <Button
                                                            size="sm"
                                                            className="mt-3 w-full rounded-xl"
                                                            onClick={() =>
                                                                handleSendQuote(q.id)
                                                            }
                                                            disabled={
                                                                sendingQuoteId === q.id
                                                            }
                                                        >
                                                            <Send className="mr-1.5 h-3.5 w-3.5" />
                                                            {sendingQuoteId === q.id
                                                                ? "Sending…"
                                                                : "Send to customer"}
                                                        </Button>
                                                    )}
                                                </div>
                                            ))}
                                        </div>

                                        {/* Quote form */}
                                        {showQuoteForm && (
                                            <div
                                                className="
                                                    mt-3
                                                    space-y-4
                                                    rounded-2xl
                                                    border
                                                    border-dashed
                                                    border-accent/30
                                                    bg-accent/[0.025]
                                                    p-4
                                                "
                                            >
                                                <div>
                                                    <p className="text-sm font-semibold">
                                                        Create quote
                                                    </p>

                                                    <p className="mt-1 text-xs text-muted-foreground">
                                                        Prepare a draft before sending it to
                                                        the customer.
                                                    </p>
                                                </div>

                                                <div className="grid grid-cols-2 gap-3">
                                                    <div className="space-y-1.5">
                                                        <Label className="text-xs">
                                                            Price / adult
                                                        </Label>

                                                        <Input
                                                            type="number"
                                                            min={0}
                                                            value={quotePricePerAdult}
                                                            onChange={(e) =>
                                                                setQuotePricePerAdult(
                                                                    e.target.value,
                                                                )
                                                            }
                                                            className="rounded-xl"
                                                        />
                                                    </div>

                                                    <div className="space-y-1.5">
                                                        <Label className="text-xs">
                                                            Price / child
                                                        </Label>

                                                        <Input
                                                            type="number"
                                                            min={0}
                                                            value={quotePricePerChild}
                                                            onChange={(e) =>
                                                                setQuotePricePerChild(
                                                                    e.target.value,
                                                                )
                                                            }
                                                            className="rounded-xl"
                                                        />
                                                    </div>
                                                </div>

                                                <div className="grid grid-cols-2 gap-3">
                                                    <div className="space-y-1.5">
                                                        <Label className="text-xs">Total price</Label>

                                                        <Input
                                                            type="number"
                                                            min={0}
                                                            value={quoteTotalPrice}
                                                            onChange={(e) => {
                                                                setQuoteTotalPrice(e.target.value);
                                                                setQuoteTotalManuallyEdited(true);
                                                            }}
                                                            className="rounded-xl"
                                                        />

                                                        {!quoteTotalManuallyEdited && detail && (
                                                            <p className="text-[11px] text-muted-foreground">
                                                                {(detail.groupSizeAdults ?? 0)} adult{(detail.groupSizeAdults ?? 0) !== 1 ? "s" : ""}
                                                                {" × "}{quoteCurrency} {Number(quotePricePerAdult || 0).toLocaleString()}
                                                                {(detail.groupSizeChildren ?? 0) > 0 && (
                                                                    <>
                                                                        {" + "}
                                                                        {(detail.groupSizeChildren ?? 0)} child
                                                                        {(detail.groupSizeChildren ?? 0) !== 1 ? "ren" : ""}
                                                                        {" × "}{quoteCurrency} {Number(quotePricePerChild || 0).toLocaleString()}
                                                                    </>
                                                                )}
                                                            </p>
                                                        )}

                                                        {quoteTotalManuallyEdited && (
                                                            <button
                                                                type="button"
                                                                onClick={() => setQuoteTotalManuallyEdited(false)}
                                                                className="text-[11px] font-medium text-primary hover:underline"
                                                            >
                                                                Reset to calculated total
                                                            </button>
                                                        )}
                                                    </div>

                                                    <div className="space-y-1.5">
                                                        <Label className="text-xs">
                                                            Currency
                                                        </Label>

                                                        <Select
                                                            value={quoteCurrency}
                                                            onValueChange={
                                                                setQuoteCurrency
                                                            }
                                                        >
                                                            <SelectTrigger className="rounded-xl">
                                                                <SelectValue />
                                                            </SelectTrigger>

                                                            <SelectContent>
                                                                <SelectItem value="KES">
                                                                    KES
                                                                </SelectItem>

                                                                <SelectItem value="USD">
                                                                    USD
                                                                </SelectItem>
                                                            </SelectContent>
                                                        </Select>
                                                    </div>
                                                </div>

                                                <div className="space-y-1.5">
                                                    <Label className="text-xs">
                                                        Valid until
                                                    </Label>

                                                    <Input
                                                        type="date"
                                                        value={quoteValidUntil}
                                                        onChange={(e) =>
                                                            setQuoteValidUntil(
                                                                e.target.value,
                                                            )
                                                        }
                                                        className="rounded-xl"
                                                    />
                                                </div>

                                                <div className="space-y-1.5">
                                                    <Label className="text-xs">
                                                        Inclusions note
                                                    </Label>

                                                    <Textarea
                                                        rows={3}
                                                        value={quoteInclusions}
                                                        onChange={(e) =>
                                                            setQuoteInclusions(
                                                                e.target.value,
                                                            )
                                                        }
                                                        className="resize-none rounded-xl"
                                                    />
                                                </div>

                                                <div className="grid grid-cols-2 gap-2">
                                                    <Button
                                                        variant="outline"
                                                        size="sm"
                                                        className="rounded-xl"
                                                        onClick={() => {
                                                            setShowQuoteForm(false);
                                                            resetQuoteForm();
                                                        }}
                                                    >
                                                        Cancel
                                                    </Button>

                                                    <Button
                                                        size="sm"
                                                        className="rounded-xl"
                                                        onClick={handleCreateQuote}
                                                        disabled={isSavingQuote}
                                                    >
                                                        {isSavingQuote
                                                            ? "Saving…"
                                                            : "Save draft"}
                                                    </Button>
                                                </div>
                                            </div>
                                        )}
                                    </section>

                                    {/* =================================
                                     * INTERNAL NOTES
                                     * ================================= */}
                                    <section>
                                        <div className="mb-3">
                                            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                                                Internal notes
                                            </p>

                                            <p className="mt-1 text-sm text-muted-foreground">
                                                Visible only to your team.
                                            </p>
                                        </div>

                                        <div className="rounded-2xl border border-amber-500/20 bg-amber-500/[0.035] p-4">
                                            <Textarea
                                                rows={3}
                                                value={noteDraft}
                                                onChange={(e) =>
                                                    setNoteDraft(e.target.value)
                                                }
                                                placeholder="Add a private note about this enquiry…"
                                                className="
                                                    resize-none
                                                    border-amber-500/20
                                                    bg-background/70
                                                    rounded-xl
                                                "
                                            />

                                            <Button
                                                variant="outline"
                                                onClick={handleAddNote}
                                                disabled={isSavingNote}
                                                className="mt-3 w-full rounded-xl"
                                            >
                                                {isSavingNote
                                                    ? "Saving…"
                                                    : "Add internal note"}
                                            </Button>
                                        </div>
                                    </section>

                                    {/* =================================
                                     * ACTIVITY TIMELINE
                                     * ================================= */}
                                    <section>
                                        <div className="mb-4">
                                            <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                                                Activity
                                            </p>

                                            <p className="mt-1 text-sm text-muted-foreground">
                                                Recent changes and communication history.
                                            </p>
                                        </div>

                                        {detail.activity.length === 0 ? (
                                            <div className="rounded-2xl border border-dashed border-border p-7 text-center">
                                                <Clock className="mx-auto h-5 w-5 text-muted-foreground/50" />

                                                <p className="mt-2 text-sm font-medium">
                                                    No activity yet
                                                </p>

                                                <p className="mt-1 text-xs text-muted-foreground">
                                                    Updates will appear here as this enquiry
                                                    progresses.
                                                </p>
                                            </div>
                                        ) : (
                                            <div className="relative">
                                                {detail.activity.map((event, index) => (
                                                    <div
                                                        key={event.id}
                                                        className="relative flex gap-4 pb-6 last:pb-0"
                                                    >
                                                        {index <
                                                            detail.activity.length - 1 && (
                                                                <div
                                                                    aria-hidden="true"
                                                                    className="
                                                                        absolute
                                                                        left-[7px]
                                                                        top-4
                                                                        h-[calc(100%-4px)]
                                                                        w-px
                                                                        bg-border
                                                                    "
                                                                />
                                                            )}

                                                        <div
                                                            className="
                                                                relative
                                                                z-10
                                                                flex
                                                                h-4
                                                                w-4
                                                                shrink-0
                                                                items-center
                                                                justify-center
                                                                rounded-full
                                                                border
                                                                border-border
                                                                bg-background
                                                            "
                                                        >
                                                            <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                                                        </div>

                                                        <div className="min-w-0 flex-1">
                                                            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                                                                <p className="text-sm font-medium capitalize">
                                                                    {event.action.replace(
                                                                        /_/g,
                                                                        " ",
                                                                    )}
                                                                </p>

                                                                <span className="text-[10px] text-muted-foreground">
                                                    {formatDateTime(
                                                        event.createdDate,
                                                    )}
                                                </span>
                                                            </div>

                                                            {event.note && (
                                                                <p className="mt-1.5 whitespace-pre-wrap text-xs leading-5 text-muted-foreground">
                                                                    {event.note}
                                                                </p>
                                                            )}
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </section>
                                </div>
                            </div>

                            {/* =========================================
                             * STICKY FOOTER
                             * ========================================= */}
                            <SheetFooter
                                className="
                                    shrink-0
                                    border-t
                                    border-border/70
                                    bg-background/95
                                    p-4
                                    backdrop-blur-xl
                                    sm:p-5
                                "
                            >
                                <Button
                                    variant="outline"
                                    onClick={closeDetail}
                                    className="w-full rounded-xl"
                                >
                                    Close enquiry
                                </Button>
                            </SheetFooter>
                        </div>
                    ) : null}
                </SheetContent>
            </Sheet>
        </div>
    );
}