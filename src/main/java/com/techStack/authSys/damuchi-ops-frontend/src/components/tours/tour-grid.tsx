"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
    Compass,
    RefreshCw,
    Search,
    SlidersHorizontal,
    X,
    ChevronLeft,
    ChevronRight,
} from "lucide-react";

import { TourShowcaseSection } from "@/components/tours/tour-showcase-section";
import { TourCardSkeleton } from "@/components/tours/tour-card-skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

import {
    CATEGORY_EMOJI,
    CATEGORY_LABELS,
    type TourCategory,
    type TourSummary,
} from "@/types/tour";
import {tourApi} from "@/lib/tour-api";

const CATEGORIES = Object.entries(CATEGORY_LABELS) as [
    TourCategory,
    string,
][];

const PAGE_SIZE = 12;

interface SearchEventDetail {
    search?: string;
    category?: string;
}

interface TourGridProps {
    initialCategory?: TourCategory | null;
    initialSearch?: string;
}

function normalizeCategory(
    value?: string | null,
): TourCategory | null {
    if (!value) return null;

    return Object.prototype.hasOwnProperty.call(
        CATEGORY_LABELS,
        value,
    )
        ? (value as TourCategory)
        : null;
}

export function TourGrid({
                             initialCategory = null,
                             initialSearch = "",
                         }: TourGridProps) {
    const [tours, setTours] = useState<TourSummary[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const [activeCategory, setActiveCategory] =
        useState<TourCategory | null>(initialCategory);

    const [activeSearch, setActiveSearch] =
        useState(initialSearch.trim());

    const [totalCount, setTotalCount] =
        useState<number | null>(null);

    const abortRef = useRef<AbortController | null>(null);
    const requestIdRef = useRef(0);
    const resultsRef = useRef<HTMLDivElement | null>(null);

    const shouldReduceMotion = useReducedMotion();

    /**
     * Load tours from the API.
     *
     * Request IDs protect against stale responses.
     * AbortController prevents unnecessary in-flight requests.
     */
    const load = useCallback(
        async (
            category?: TourCategory | null,
            query?: string,
        ) => {
            const requestId = ++requestIdRef.current;

            abortRef.current?.abort();

            const controller = new AbortController();
            abortRef.current = controller;

            setIsLoading(true);
            setError(null);

            try {
                // tourApi.getTours already branches internally: if a search
                // term is present it delegates to searchTours for you, so no
                // manual if/else is needed here like there was for tourAdminApi.
                const data = await tourApi.getTours({
                    page: 0,
                    size: PAGE_SIZE,
                    category: category ?? undefined,
                    q: query,
                    signal: controller.signal,
                });

                if (
                    controller.signal.aborted ||
                    requestId !== requestIdRef.current
                ) {
                    return;
                }

                setTours(data.content);
                setTotalCount(data.totalElements);
            } catch (err: unknown) {
                // fetch throws a real DOMException named "AbortError" when the
                // signal fires — tourApi's `request()` doesn't wrap that, so it
                // reaches here as-is, not as tourApi's usual plain-object shape.
                const isAbort =
                    controller.signal.aborted ||
                    (err instanceof DOMException && err.name === "AbortError") ||
                    (typeof err === "object" && err !== null && "name" in err && (err as { name?: unknown }).name === "AbortError");

                if (isAbort || requestId !== requestIdRef.current) {
                    return;
                }

                // tourApi's `request()` helper throws a plain object
                // { message, statusCode, code } — NOT an Error instance — so
                // `err instanceof Error` (which the old code relied on) never
                // matched and every failure fell through to the generic
                // message, hiding the real API error. Check for a `message`
                // property structurally instead.
                const message =
                    typeof err === "object" && err !== null && "message" in err
                        ? String((err as { message?: unknown }).message)
                        : "Couldn't load tours right now.";

                setError(message);
                setTours([]);
                setTotalCount(null);
            } finally {
                if (
                    requestId === requestIdRef.current &&
                    !controller.signal.aborted
                ) {
                    setIsLoading(false);
                }
            }
        },
        [],
    );

    useEffect(() => {
        void load(initialCategory, initialSearch);

        return () => {
            requestIdRef.current += 1;
            abortRef.current?.abort();
        };
    }, [load, initialCategory, initialSearch]);

    /**
     * Hero / global search integration.
     */
    useEffect(() => {
        function handleSearch(event: Event) {
            const customEvent =
                event as CustomEvent<SearchEventDetail>;

            const detail = customEvent.detail ?? {};

            const search =
                detail.search?.trim() ?? "";

            const category =
                normalizeCategory(detail.category);

            setActiveSearch(search);
            setActiveCategory(category);

            void load(category, search);

            requestAnimationFrame(() => {
                document
                    .getElementById("tours")
                    ?.scrollIntoView({
                        behavior: shouldReduceMotion
                            ? "auto"
                            : "smooth",
                        block: "start",
                    });
            });
        }

        /**
         * Keep this event name consistent with HeroSearch.
         */
        window.addEventListener(
            "basecamp:search",
            handleSearch,
        );

        return () => {
            window.removeEventListener(
                "basecamp:search",
                handleSearch,
            );
        };
    }, [load, shouldReduceMotion]);

    const handleCategoryClick = (
        category: TourCategory | null,
    ) => {
        setActiveCategory(category);

        void load(category, activeSearch);
    };

    const clearFilters = () => {
        setActiveSearch("");
        setActiveCategory(null);

        void load(null, "");
    };

    const hasFilters =
        Boolean(activeSearch) ||
        activeCategory !== null;

    return (
        <section
            id="tours"
            aria-labelledby="tour-catalogue-heading"
            className="
                relative
                scroll-mt-24
                overflow-hidden
                py-8
                sm:py-10
                lg:py-12
            "
        >
            {/* Atmospheric background */}
            <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0"
            >
                <div
                    className="
                        absolute
                        left-1/2
                        top-0
                        h-72
                        w-[min(900px,100%)]
                        -translate-x-1/2
                        rounded-full
                        bg-expedition-clay/5
                        blur-3xl
                    "
                />

                <div
                    className="
                        absolute
                        right-0
                        top-1/3
                        h-64
                        w-64
                        rounded-full
                        bg-accent/5
                        blur-3xl
                    "
                />
            </div>

            <div className="container relative">
                {/* Section heading */}
                <motion.div
                    initial={
                        shouldReduceMotion
                            ? false
                            : {
                                opacity: 0,
                                y: 20,
                            }
                    }
                    whileInView={
                        shouldReduceMotion
                            ? undefined
                            : {
                                opacity: 1,
                                y: 0,
                            }
                    }
                    viewport={{
                        once: true,
                        amount: 0.25,
                    }}
                    transition={{
                        duration: 0.55,
                        ease: "easeOut",
                    }}
                    className="mx-auto max-w-3xl text-center"
                >
                    <div
                        className="
                            inline-flex
                            items-center
                            gap-2
                            rounded-full
                            border
                            border-accent/20
                            bg-accent/5
                            px-3
                            py-1.5
                        "
                    >
                        <Compass
                            className="h-3.5 w-3.5 text-accent"
                            aria-hidden="true"
                        />

                        <span
                            className="
                                font-mono
                                text-[10px]
                                font-semibold
                                uppercase
                                tracking-[0.18em]
                                text-accent
                            "
                        >
                            The Safari Catalogue
                        </span>
                    </div>

                    <h2
                        id="tour-catalogue-heading"
                        className="
                            mt-4
                            font-display
                            text-3xl
                            font-medium
                            tracking-tight
                            text-foreground
                            sm:text-4xl
                            lg:text-5xl
                        "
                    >
                        Journeys worth
                        <span className="text-accent">
                            {" "}
                            rearranging your year for.
                        </span>
                    </h2>

                    <p
                        className="
                            mx-auto
                            mt-4
                            max-w-2xl
                            text-sm
                            leading-7
                            text-muted-foreground
                            sm:text-base
                        "
                    >
                        From wildlife-filled savannahs to Indian
                        Ocean escapes, discover thoughtfully curated
                        journeys led by people who know East Africa
                        intimately.
                    </p>
                </motion.div>

                {/* Category filters */}
                <motion.div
                    initial={
                        shouldReduceMotion
                            ? false
                            : {
                                opacity: 0,
                                y: 12,
                            }
                    }
                    whileInView={
                        shouldReduceMotion
                            ? undefined
                            : {
                                opacity: 1,
                                y: 0,
                            }
                    }
                    viewport={{
                        once: true,
                        amount: 0.15,
                    }}
                    transition={{
                        duration: 0.5,
                        delay: 0.08,
                        ease: "easeOut",
                    }}
                    className="mt-8"
                >
                    <div
                        className="
                            flex
                            items-center
                            justify-center
                            gap-2
                            text-xs
                            font-medium
                            uppercase
                            tracking-wider
                            text-muted-foreground
                        "
                    >
                        <SlidersHorizontal
                            className="h-3.5 w-3.5"
                            aria-hidden="true"
                        />

                        <span>
                            Explore by experience
                        </span>
                    </div>

                    <div
                        className="
                            mt-4
                            flex
                            flex-wrap
                            items-center
                            justify-center
                            gap-2
                        "
                        role="group"
                        aria-label="Filter tours by category"
                    >
                        <button
                            type="button"
                            onClick={() =>
                                handleCategoryClick(null)
                            }
                            aria-pressed={
                                activeCategory === null
                            }
                            className={cn(
                                "rounded-full border px-4 py-2 text-sm font-medium",
                                "transition-all duration-200",
                                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                                activeCategory === null
                                    ? "border-accent bg-accent text-accent-foreground shadow-sm shadow-accent/20"
                                    : "border-border bg-background/70 text-muted-foreground hover:border-accent/40 hover:bg-accent/5 hover:text-foreground",
                            )}
                        >
                            All tours
                        </button>

                        {CATEGORIES.map(
                            ([value, label]) => {
                                const active =
                                    activeCategory === value;

                                return (
                                    <button
                                        key={value}
                                        type="button"
                                        onClick={() =>
                                            handleCategoryClick(
                                                value,
                                            )
                                        }
                                        aria-pressed={active}
                                        className={cn(
                                            "rounded-full border px-4 py-2 text-sm font-medium",
                                            "transition-all duration-200",
                                            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                                            active
                                                ? "border-accent bg-accent text-accent-foreground shadow-sm shadow-accent/20"
                                                : "border-border bg-background/70 text-muted-foreground hover:border-accent/40 hover:bg-accent/5 hover:text-foreground",
                                        )}
                                    >
                                        <span aria-hidden="true">
                                            {
                                                CATEGORY_EMOJI[
                                                    value
                                                    ]
                                            }
                                        </span>{" "}
                                        {label}
                                    </button>
                                );
                            },
                        )}
                    </div>
                </motion.div>

                {/* Result summary */}
                <div className="mt-7 min-h-7">
                    <AnimatePresence mode="wait">
                        {!isLoading &&
                        !error &&
                        totalCount !== null ? (
                            <motion.div
                                key={`${activeSearch}-${activeCategory}-${totalCount}`}
                                initial={
                                    shouldReduceMotion
                                        ? false
                                        : {
                                            opacity: 0,
                                            y: 5,
                                        }
                                }
                                animate={{
                                    opacity: 1,
                                    y: 0,
                                }}
                                exit={
                                    shouldReduceMotion
                                        ? undefined
                                        : {
                                            opacity: 0,
                                            y: -5,
                                        }
                                }
                                className="
                                    flex
                                    flex-wrap
                                    items-center
                                    justify-center
                                    gap-2
                                    text-sm
                                    text-muted-foreground
                                "
                            >
                                <span>
                                    {totalCount === 0
                                        ? "No tours match your search"
                                        : `${totalCount.toLocaleString(
                                            "en-KE",
                                        )} tour${
                                            totalCount !== 1
                                                ? "s"
                                                : ""
                                        } available`}
                                </span>

                                {activeSearch && (
                                    <span
                                        className="
                                            inline-flex
                                            items-center
                                            gap-1
                                            rounded-full
                                            bg-muted
                                            px-2.5
                                            py-1
                                        "
                                    >
                                        <Search
                                            className="h-3 w-3"
                                            aria-hidden="true"
                                        />

                                        &ldquo;
                                        {activeSearch}
                                        &rdquo;
                                    </span>
                                )}

                                {activeCategory && (
                                    <span
                                        className="
                                            rounded-full
                                            bg-muted
                                            px-2.5
                                            py-1
                                        "
                                    >
                                        {
                                            CATEGORY_LABELS[
                                                activeCategory
                                                ]
                                        }
                                    </span>
                                )}

                                {hasFilters && (
                                    <button
                                        type="button"
                                        onClick={
                                            clearFilters
                                        }
                                        className="
                                            inline-flex
                                            items-center
                                            gap-1
                                            rounded-full
                                            px-2.5
                                            py-1
                                            text-xs
                                            font-medium
                                            text-accent
                                            transition-colors
                                            hover:bg-accent/10
                                        "
                                    >
                                        <X
                                            className="h-3 w-3"
                                            aria-hidden="true"
                                        />
                                        Clear
                                    </button>
                                )}
                            </motion.div>
                        ) : null}
                    </AnimatePresence>
                </div>

                {/* Listings */}
                <div
                    className="mt-8 min-w-0"
                    aria-live="polite"
                    aria-busy={isLoading}
                    aria-label="Tour listings"
                >
                    <AnimatePresence
                        mode="wait"
                        initial={false}
                    >
                        {isLoading ? (
                            /* =========================
                             * LOADING
                             * ========================= */
                            <motion.div
                                key="loading"
                                initial={
                                    shouldReduceMotion
                                        ? false
                                        : { opacity: 0 }
                                }
                                animate={{
                                    opacity: 1,
                                }}
                                exit={
                                    shouldReduceMotion
                                        ? undefined
                                        : { opacity: 0 }
                                }
                                className="
                                    grid
                                    grid-cols-1
                                    gap-5
                                    sm:grid-cols-2
                                    lg:grid-cols-3
                                "
                            >
                                {Array.from({ length: 6 }).map((_, index) => (
                                    <TourCardSkeleton key={index} />
                                ))}
                            </motion.div>

                        ) : error ? (
                            /* =========================
                             * ERROR
                             * ========================= */
                            <motion.div
                                key="error"
                                initial={
                                    shouldReduceMotion
                                        ? false
                                        : {
                                            opacity: 0,
                                            y: 10,
                                        }
                                }
                                animate={{
                                    opacity: 1,
                                    y: 0,
                                }}
                            >
                                <EmptyState
                                    icon={RefreshCw}
                                    title="Couldn't load the safari catalogue"
                                    description={error}
                                    action={
                                        <Button
                                            variant="outline"
                                            onClick={() =>
                                                void load(
                                                    activeCategory,
                                                    activeSearch,
                                                )
                                            }
                                        >
                                            <RefreshCw
                                                className="mr-2 h-4 w-4"
                                                aria-hidden="true"
                                            />
                                            Try again
                                        </Button>
                                    }
                                />
                            </motion.div>

                        ) : tours.length === 0 ? (
                            /* =========================
                             * EMPTY
                             * ========================= */
                            <motion.div
                                key="empty"
                                initial={
                                    shouldReduceMotion
                                        ? false
                                        : {
                                            opacity: 0,
                                            y: 10,
                                        }
                                }
                                animate={{
                                    opacity: 1,
                                    y: 0,
                                }}
                            >
                                <EmptyState
                                    icon={Compass}
                                    title="No journeys match yet"
                                    description={
                                        hasFilters
                                            ? "Try a different destination, category, or search term."
                                            : "New adventures are added regularly. Check back soon."
                                    }
                                    action={
                                        hasFilters ? (
                                            <Button
                                                variant="outline"
                                                onClick={clearFilters}
                                            >
                                                <X
                                                    className="mr-2 h-4 w-4"
                                                    aria-hidden="true"
                                                />
                                                Clear filters
                                            </Button>
                                        ) : undefined
                                    }
                                />
                            </motion.div>

                        ) : (
                            /* =========================
                             * RESULTS / CAROUSEL
                             * ========================= */
                            <motion.div
                                key="results"
                                initial={
                                    shouldReduceMotion
                                        ? false
                                        : {
                                            opacity: 0,
                                            y: 20,
                                        }
                                }
                                animate={{
                                    opacity: 1,
                                    y: 0,
                                }}
                                transition={{
                                    duration: 0.5,
                                    ease: [0.22, 1, 0.36, 1],
                                }}
                            >
                                <TourShowcaseSection tours={tours} />
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </section>
);
}