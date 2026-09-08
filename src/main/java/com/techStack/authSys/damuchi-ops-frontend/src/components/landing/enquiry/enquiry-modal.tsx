"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
    ArrowLeft,
    ArrowRight,
    Check,
    Loader2,
    MapPin,
    MessageSquarePlus,
    Search,
    Sparkles,
} from "lucide-react";

import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EnquiryForm } from "@/components/landing/enquiry/enquiry-form";
import { tourApi } from "@/lib/tour-api";
import type { TourSummary } from "@/types/tour";

interface EnquiryModalProps {
    /** Custom trigger. Falls back to the default Enquire button. */
    children?: React.ReactNode;

    /** Analytics/source identifier passed to EnquiryForm. */
    source?: string;

    /**
     * When provided:
     * - the modal opens directly on this tour
     * - no tour-list API request is made
     * - the enquiry form receives this tour automatically
     *
     * When omitted:
     * - the user sees the tour picker first
     */
    tour?: TourSummary;
}

export function EnquiryModal({
    children,
    source = "nav-enquire-modal",
    tour,
}: EnquiryModalProps) {
    const [open, setOpen] = useState(false);

    const [tours, setTours] = useState<TourSummary[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(false);

    const [selectedTour, setSelectedTour] =
        useState<TourSummary | null>(tour ?? null);

    const [search, setSearch] = useState("");

    /**
     * Keep the selected tour synchronized when the parent
     * changes the tour prop.
     */
    useEffect(() => {
        if (tour) {
            setSelectedTour(tour);
        }
    }, [tour]);

    /**
     * Fetch tours only when:
     * - the modal is open
     * - there isn't already a preselected tour
     * - tours haven't already been loaded
     */
    const loadTours = useCallback(async () => {
        setLoading(true);
        setError(false);

        try {
            const data = await tourApi.getTours();
            setTours(data.content);
        } catch {
            setTours([]);
            setError(true);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        if (!open || tour || tours.length > 0) {
            return;
        }

        let cancelled = false;

        async function fetchTours() {
            setLoading(true);
            setError(false);

            try {
                const data = await tourApi.getTours();

                if (!cancelled) {
                    setTours(data.content);
                }
            } catch {
                if (!cancelled) {
                    setTours([]);
                    setError(true);
                }
            } finally {
                if (!cancelled) {
                    setLoading(false);
                }
            }
        }

        void fetchTours();

        return () => {
            cancelled = true;
        };
    }, [open, tour, tours.length]);

    /**
     * Modal lifecycle.
     */
    function handleOpenChange(next: boolean) {
        setOpen(next);

        if (next) {
            // TourCard / detail page → direct to form.
            if (tour) {
                setSelectedTour(tour);
            }

            return;
        }

        // Clean transient UI state when closing.
        setSearch("");

        // Navbar/global enquiry modal should return to
        // tour selection the next time it opens.
        if (!tour) {
            setSelectedTour(null);
        }
    }

    /**
     * Go back to the tour picker.
     *
     * Only available when the modal wasn't opened with
     * a preselected tour.
     */
    function handleBack() {
        if (tour) {
            return;
        }

        setSelectedTour(null);
    }

    function handleSelectTour(nextTour: TourSummary) {
        setSelectedTour(nextTour);
    }

    const filteredTours = useMemo(() => {
        const query = search.trim().toLowerCase();

        if (!query) {
            return tours;
        }

        return tours.filter((item) =>
            `${item.name} ${item.destination} ${item.category}`
                .toLowerCase()
                .includes(query),
        );
    }, [search, tours]);

    const isSelectingTour = selectedTour === null;

    return (
        <Dialog open={open} onOpenChange={handleOpenChange}>
            <DialogTrigger asChild>
                {children ?? (
                    <Button
                        variant="accent"
                        size="sm"
                        className="
                            gap-2
                            shadow-sm
                            transition-all
                            hover:-translate-y-0.5
                            hover:shadow-md
                            active:translate-y-0
                        "
                    >
                        <MessageSquarePlus className="h-4 w-4" />
                        Enquire
                    </Button>
                )}
            </DialogTrigger>

            <DialogContent
                className="
                    flex
                    h-[100dvh]
                    w-full
                    max-w-none
                    flex-col
                    gap-0
                    overflow-hidden
                    border-0
                    bg-background/95
                    p-0
                    shadow-2xl
                    backdrop-blur-2xl

                    sm:h-auto
                    sm:max-h-[min(760px,90dvh)]
                    sm:max-w-[560px]
                    sm:rounded-3xl
                    sm:border
                    sm:border-white/10

                    lg:max-w-[600px]

                    dark:bg-background/90
                "
            >
                {/* ─────────────────────────────────────────
                    AMBIENT GLASS EFFECT
                ───────────────────────────────────────── */}
                <div
                    aria-hidden="true"
                    className="
                        pointer-events-none
                        absolute
                        -right-24
                        -top-24
                        h-64
                        w-64
                        rounded-full
                        bg-primary/10
                        blur-3xl
                    "
                />

                {/* ─────────────────────────────────────────
                    HEADER
                ───────────────────────────────────────── */}
                <DialogHeader
                    className="
                        relative
                        shrink-0
                        border-b
                        border-border/50
                        px-5
                        pb-4
                        pt-5

                        sm:px-6
                        sm:pb-5
                        sm:pt-6
                    "
                >
                    {selectedTour ? (
                        <div className="space-y-3">
                            {/* Back to tour selection */}
                            {!tour && (
                                <button
                                    type="button"
                                    onClick={handleBack}
                                    className="
                                        inline-flex
                                        items-center
                                        gap-1.5
                                        text-xs
                                        font-medium
                                        text-muted-foreground
                                        transition-colors
                                        hover:text-foreground
                                        focus-visible:outline-none
                                        focus-visible:ring-2
                                        focus-visible:ring-primary/40
                                        focus-visible:ring-offset-2
                                        rounded-md
                                    "
                                >
                                    <ArrowLeft className="h-3.5 w-3.5" />
                                    Choose another tour
                                </button>
                            )}

                            <div className="flex items-start gap-3">
                                <div
                                    className="
                                        flex
                                        h-9
                                        w-9
                                        shrink-0
                                        items-center
                                        justify-center
                                        rounded-xl
                                        bg-primary/10
                                        text-primary
                                    "
                                >
                                    <MessageSquarePlus className="h-4 w-4" />
                                </div>

                                <div className="min-w-0">
                                    <DialogTitle
                                        className="
                                            font-display
                                            text-xl
                                            font-semibold
                                            tracking-tight
                                        "
                                    >
                                        Make an enquiry
                                    </DialogTitle>

                                    <DialogDescription className="mt-1 truncate text-xs">
                                        Tell us a little about your trip and
                                        we'll help plan the details.
                                    </DialogDescription>
                                </div>
                            </div>

                            {/* Selected tour context */}
                            <AnimatePresence mode="wait" initial={false}>
                                <motion.div
                                    key={selectedTour.id}
                                    initial={{
                                        opacity: 0,
                                        y: -6,
                                    }}
                                    animate={{
                                        opacity: 1,
                                        y: 0,
                                    }}
                                    exit={{
                                        opacity: 0,
                                        y: -6,
                                    }}
                                    transition={{
                                        duration: 0.2,
                                    }}
                                >
                                    <div
                                        className="
                                            flex
                                            min-w-0
                                            items-center
                                            gap-2.5
                                            rounded-xl
                                            border
                                            border-primary/10
                                            bg-primary/[0.045]
                                            px-3
                                            py-2.5
                                        "
                                    >
                                        <div
                                            className="
                                                flex
                                                h-7
                                                w-7
                                                shrink-0
                                                items-center
                                                justify-center
                                                rounded-lg
                                                bg-background/80
                                            "
                                        >
                                            <Check className="h-3.5 w-3.5 text-primary" />
                                        </div>

                                        <div className="min-w-0">
                                            <p className="truncate text-xs font-semibold">
                                                {selectedTour.name}
                                            </p>

                                            <p className="mt-0.5 flex items-center gap-1 text-[10px] text-muted-foreground">
                                                <MapPin className="h-3 w-3 shrink-0" />

                                                <span className="truncate">
                                                    {
                                                        selectedTour.destination
                                                    }
                                                </span>
                                            </p>
                                        </div>

                                        {!tour && (
                                            <button
                                                type="button"
                                                onClick={handleBack}
                                                className="
                                                    ml-auto
                                                    shrink-0
                                                    text-[11px]
                                                    font-medium
                                                    text-muted-foreground
                                                    transition-colors
                                                    hover:text-foreground
                                                    focus-visible:outline-none
                                                    focus-visible:ring-2
                                                    focus-visible:ring-primary/40
                                                    rounded-sm
                                                "
                                            >
                                                Change
                                            </button>
                                        )}
                                    </div>
                                </motion.div>
                            </AnimatePresence>
                        </div>
                    ) : (
                        <div className="space-y-3">
                            <div className="flex items-start gap-3">
                                <div
                                    className="
                                        flex
                                        h-10
                                        w-10
                                        shrink-0
                                        items-center
                                        justify-center
                                        rounded-xl
                                        bg-primary/10
                                        text-primary
                                        shadow-sm
                                    "
                                >
                                    <Sparkles className="h-5 w-5" />
                                </div>

                                <div className="min-w-0 flex-1">
                                    <DialogTitle
                                        className="
                                            font-display
                                            text-xl
                                            font-semibold
                                            tracking-tight

                                            sm:text-2xl
                                        "
                                    >
                                        Plan your trip
                                    </DialogTitle>

                                    <DialogDescription className="mt-1 text-xs leading-5">
                                        Choose a tour you're interested in and
                                        we'll help you plan the rest.
                                    </DialogDescription>
                                </div>
                            </div>

                            {/* Search */}
                            {!loading && tours.length > 0 && (
                                <div className="relative">
                                    <Search
                                        className="
                                            pointer-events-none
                                            absolute
                                            left-3
                                            top-1/2
                                            h-4
                                            w-4
                                            -translate-y-1/2
                                            text-muted-foreground
                                        "
                                    />

                                    <Input
                                        value={search}
                                        onChange={(event) =>
                                            setSearch(event.target.value)
                                        }
                                        placeholder="Search tours or destinations…"
                                        className="
                                            h-10
                                            rounded-xl
                                            border-border/60
                                            bg-background/50
                                            pl-9
                                            text-sm
                                            backdrop-blur
                                        "
                                        aria-label="Search tours"
                                    />
                                </div>
                            )}
                        </div>
                    )}
                </DialogHeader>

                {/* ─────────────────────────────────────────
                    BODY
                ───────────────────────────────────────── */}
                <div
                    className="
                        min-h-0
                        flex-1
                        overflow-y-auto
                        overscroll-contain
                    "
                >
                    <AnimatePresence mode="wait" initial={false}>
                        {loading ? (
                            <motion.div
                                key="loading"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="
                                    flex
                                    min-h-[320px]
                                    flex-col
                                    items-center
                                    justify-center
                                    gap-3
                                    px-6
                                "
                            >
                                <div
                                    className="
                                        flex
                                        h-11
                                        w-11
                                        items-center
                                        justify-center
                                        rounded-2xl
                                        bg-primary/10
                                    "
                                >
                                    <Loader2 className="h-5 w-5 animate-spin text-primary" />
                                </div>

                                <div className="text-center">
                                    <p className="text-sm font-medium">
                                        Finding available tours
                                    </p>

                                    <p className="mt-1 text-xs text-muted-foreground">
                                        Just a moment…
                                    </p>
                                </div>
                            </motion.div>
                        ) : selectedTour ? (
                            <motion.div
                                key={`form-${selectedTour.id}`}
                                initial={{
                                    opacity: 0,
                                    x: 10,
                                }}
                                animate={{
                                    opacity: 1,
                                    x: 0,
                                }}
                                exit={{
                                    opacity: 0,
                                    x: -10,
                                }}
                                transition={{
                                    duration: 0.2,
                                    ease: "easeOut",
                                }}
                                className="px-5 py-5 sm:px-6 sm:py-6"
                            >
                                <EnquiryForm
                                    tourId={selectedTour.id}
                                    tourName={selectedTour.name}
                                    source={source}
                                    onSuccess={() =>
                                        handleOpenChange(false)
                                    }
                                />
                            </motion.div>
                        ) : error ? (
                            <motion.div
                                key="error"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="
                                    flex
                                    min-h-[320px]
                                    flex-col
                                    items-center
                                    justify-center
                                    px-6
                                    text-center
                                "
                            >
                                <div
                                    className="
                                        flex
                                        h-11
                                        w-11
                                        items-center
                                        justify-center
                                        rounded-2xl
                                        bg-muted
                                    "
                                >
                                    <MessageSquarePlus className="h-5 w-5 text-muted-foreground" />
                                </div>

                                <p className="mt-4 text-sm font-medium">
                                    We couldn't load the tours
                                </p>

                                <p className="mt-1 max-w-xs text-xs leading-5 text-muted-foreground">
                                    Please try again in a moment.
                                </p>

                                <Button
                                    type="button"
                                    variant="outline"
                                    size="sm"
                                    className="mt-4 rounded-full"
                                    onClick={() => void loadTours()}
                                >
                                    Try again
                                </Button>
                            </motion.div>
                        ) : isSelectingTour && tours.length === 0 ? (
                            <motion.div
                                key="empty"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="
                                    flex
                                    min-h-[320px]
                                    flex-col
                                    items-center
                                    justify-center
                                    px-6
                                    text-center
                                "
                            >
                                <div
                                    className="
                                        flex
                                        h-12
                                        w-12
                                        items-center
                                        justify-center
                                        rounded-2xl
                                        bg-muted
                                    "
                                >
                                    <MessageSquarePlus className="h-5 w-5 text-muted-foreground" />
                                </div>

                                <p className="mt-4 text-sm font-medium">
                                    No tours available
                                </p>

                                <p className="mt-1 max-w-xs text-xs leading-5 text-muted-foreground">
                                    There aren't any tours available for
                                    enquiry right now. Please check back soon.
                                </p>
                            </motion.div>
                        ) : filteredTours.length === 0 ? (
                            <motion.div
                                key="no-results"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="
                                    flex
                                    min-h-[260px]
                                    flex-col
                                    items-center
                                    justify-center
                                    px-6
                                    text-center
                                "
                            >
                                <Search className="h-5 w-5 text-muted-foreground" />

                                <p className="mt-3 text-sm font-medium">
                                    No matching tours
                                </p>

                                <p className="mt-1 text-xs text-muted-foreground">
                                    Try another tour name or destination.
                                </p>
                            </motion.div>
                        ) : (
                            <motion.div
                                key="tour-list"
                                initial={{
                                    opacity: 0,
                                    y: 6,
                                }}
                                animate={{
                                    opacity: 1,
                                    y: 0,
                                }}
                                exit={{
                                    opacity: 0,
                                    y: -6,
                                }}
                                transition={{
                                    duration: 0.2,
                                }}
                                className="px-5 py-5 sm:px-6 sm:py-6"
                            >
                                <div className="mb-3 flex items-center justify-between">
                                    <p
                                        className="
                                            text-xs
                                            font-semibold
                                            uppercase
                                            tracking-[0.12em]
                                            text-muted-foreground
                                        "
                                    >
                                        Available tours
                                    </p>

                                    <span className="text-[10px] text-muted-foreground">
                                        {filteredTours.length}{" "}
                                        {filteredTours.length === 1
                                            ? "option"
                                            : "options"}
                                    </span>
                                </div>

                                <div className="grid gap-2.5">
                                    {filteredTours.map((item) => (
                                        <button
                                            key={item.id}
                                            type="button"
                                            onClick={() =>
                                                handleSelectTour(item)
                                            }
                                            className="
                                                group
                                                flex
                                                w-full
                                                items-center
                                                gap-3
                                                rounded-2xl
                                                border
                                                border-border/60
                                                bg-background/50
                                                p-3
                                                text-left
                                                shadow-sm
                                                backdrop-blur
                                                transition-all

                                                hover:-translate-y-0.5
                                                hover:border-primary/25
                                                hover:bg-primary/[0.035]
                                                hover:shadow-md

                                                focus-visible:outline-none
                                                focus-visible:ring-2
                                                focus-visible:ring-primary
                                                focus-visible:ring-offset-2
                                            "
                                        >
                                            {/* Tour icon */}
                                            <div
                                                className="
                                                    flex
                                                    h-11
                                                    w-11
                                                    shrink-0
                                                    items-center
                                                    justify-center
                                                    overflow-hidden
                                                    rounded-xl
                                                    bg-muted
                                                    transition-colors
                                                    group-hover:bg-primary/10
                                                    group-hover:text-primary
                                                "
                                            >
                                                {item.coverImageUrl ? (
                                                    <img
                                                        src={item.coverImageUrl}
                                                        alt=""
                                                        className="h-full w-full object-cover"
                                                        loading="lazy"
                                                    />
                                                ) : (
                                                    <MapPin className="h-4 w-4" />
                                                )}
                                            </div>

                                            {/* Tour information */}
                                            <div className="min-w-0 flex-1">
                                                <p className="truncate text-sm font-semibold">
                                                    {item.name}
                                                </p>

                                                <p className="mt-1 flex items-center gap-1 text-[11px] text-muted-foreground">
                                                    <MapPin className="h-3 w-3 shrink-0" />

                                                    <span className="truncate">
                                                        {item.destination}
                                                    </span>
                                                </p>
                                            </div>

                                            {/* Arrow */}
                                            <div
                                                className="
                                                    flex
                                                    h-8
                                                    w-8
                                                    shrink-0
                                                    items-center
                                                    justify-center
                                                    rounded-lg
                                                    bg-muted/70
                                                    text-muted-foreground
                                                    transition-all

                                                    group-hover:bg-primary
                                                    group-hover:text-primary-foreground
                                                "
                                            >
                                                <ArrowRight
                                                    className="
                                                        h-3.5
                                                        w-3.5
                                                        transition-transform
                                                        group-hover:translate-x-0.5
                                                    "
                                                />
                                            </div>
                                        </button>
                                    ))}
                                </div>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                {/* ─────────────────────────────────────────
                    FOOTER
                ───────────────────────────────────────── */}
                <div
                    className="
                        shrink-0
                        border-t
                        border-border/50
                        bg-background/75
                        px-5
                        py-3
                        backdrop-blur-xl

                        sm:px-6
                        sm:py-4

                        pb-[calc(0.75rem+env(safe-area-inset-bottom))]
                    "
                >
                    <div className="flex items-center justify-between gap-3">
                        <p className="text-[10px] leading-4 text-muted-foreground">
                            Your details are handled securely.
                        </p>

                        <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => handleOpenChange(false)}
                            className="shrink-0"
                        >
                            Close
                        </Button>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    );
}
