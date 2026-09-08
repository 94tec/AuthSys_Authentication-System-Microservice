"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { motion, useReducedMotion } from "framer-motion";
import {
    ArrowUpRight,
    Clock3,
    MapPin,
    MessageCircleQuestion,
    Star,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
    CATEGORY_LABELS,
    CATEGORY_EMOJI,
    DIFFICULTY_LABELS,
    type TourSummary,
} from "@/types/tour";
import {EnquiryModal} from "@/components/landing/enquiry/enquiry-modal";

const DIFFICULTY_VARIANT = {
    EASY: "success",
    MODERATE: "secondary",
    CHALLENGING: "warning",
    STRENUOUS: "destructive",
} as const;

interface TourCardProps {
    tour: TourSummary;
}

export function TourCard({ tour }: TourCardProps) {
    const shouldReduceMotion = useReducedMotion();
    const router = useRouter();

    const emoji = CATEGORY_EMOJI[tour.category];
    const categoryLabel = CATEGORY_LABELS[tour.category];

    const hasRating =
        tour.averageRating !== null &&
        tour.averageRating !== undefined &&
        tour.averageRating > 0;

    const formattedPrice = (tour.price ?? 0).toLocaleString("en-KE");

    function goToTour() {
        router.push(`/tours/${tour.slug}`);
    }

    return (
        <motion.article
            initial={
                shouldReduceMotion
                    ? false
                    : {
                        opacity: 0,
                        y: 14,
                    }
            }
            animate={{
                opacity: 1,
                y: 0,
            }}
            whileHover={
                shouldReduceMotion
                    ? undefined
                    : {
                        y: -4,
                    }
            }
            transition={{
                duration: 0.4,
                ease: [0.22, 1, 0.36, 1],
            }}
            className="h-full min-w-0"
        >
            <div
                role="link"
                tabIndex={0}
                onClick={goToTour}
                onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        goToTour();
                    }
                }}
                aria-label={`View ${tour.name}`}
                className="
                    group
                    relative
                    flex
                    h-full
                    min-w-0
                    cursor-pointer
                    flex-col
                    overflow-hidden
                    rounded-3xl
                    border
                    border-border/70
                    bg-card
                    shadow-sm
                    transition-all
                    duration-500
                    hover:border-accent/30
                    hover:shadow-2xl
                    hover:shadow-black/[0.08]
                    focus-visible:outline-none
                    focus-visible:ring-2
                    focus-visible:ring-ring
                    focus-visible:ring-offset-2
                    dark:hover:shadow-black/20
                "
            >
                {/* ========================================
                    IMAGE
                ======================================== */}
                <div
                    className="
                        relative
                        aspect-[16/10]
                        w-full
                        shrink-0
                        overflow-hidden
                        bg-muted
                        sm:aspect-[16/9]
                    "
                >
                    {tour.coverImageUrl ? (
                        <>
                            <img
                                src={tour.coverImageUrl}
                                alt={tour.name}
                                loading="lazy"
                                className="
                                    absolute
                                    inset-0
                                    h-full
                                    w-full
                                    object-cover
                                    transition-transform
                                    duration-700
                                    ease-[cubic-bezier(0.22,1,0.36,1)]
                                    group-hover:scale-[1.045]
                                "
                            />

                            {/* Overall image atmosphere */}
                            <div
                                aria-hidden="true"
                                className="
                                    absolute
                                    inset-0
                                    bg-gradient-to-b
                                    from-black/30
                                    via-transparent
                                    to-black/70
                                    opacity-90
                                    transition-opacity
                                    duration-500
                                    group-hover:opacity-100
                                "
                            />

                            {/* Bottom cinematic fade */}
                            <div
                                aria-hidden="true"
                                className="
                                    absolute
                                    inset-x-0
                                    bottom-0
                                    h-1/2
                                    bg-gradient-to-t
                                    from-black/55
                                    via-black/10
                                    to-transparent
                                "
                            />

                            {/* Subtle image shine */}
                            <div
                                aria-hidden="true"
                                className="
                                    absolute
                                    inset-0
                                    bg-gradient-to-tr
                                    from-transparent
                                    via-white/[0.04]
                                    to-white/[0.10]
                                    opacity-0
                                    transition-opacity
                                    duration-500
                                    group-hover:opacity-100
                                "
                            />
                        </>
                    ) : (
                        <div
                            className="
                                flex
                                h-full
                                w-full
                                flex-col
                                items-center
                                justify-center
                                gap-3
                                bg-gradient-to-br
                                from-expedition-moss/20
                                via-expedition-forest/15
                                to-expedition-clay/30
                            "
                        >
                            <motion.span
                                aria-hidden="true"
                                animate={
                                    shouldReduceMotion
                                        ? undefined
                                        : {
                                            y: [0, -5, 0],
                                            scale: [1, 1.03, 1],
                                        }
                                }
                                transition={{
                                    duration: 4,
                                    repeat: Infinity,
                                    ease: "easeInOut",
                                }}
                                className="text-5xl drop-shadow-sm"
                            >
                                {emoji}
                            </motion.span>

                            <span className="font-display text-xs font-medium text-muted-foreground">
                                {categoryLabel}
                            </span>
                        </div>
                    )}

                    {/* ========================================
                        TOP LEFT — CATEGORY
                    ======================================== */}
                    <div className="absolute left-3.5 top-3.5 sm:left-4 sm:top-4">
                        <Badge
                            variant="secondary"
                            className="
                                max-w-[calc(100vw-7rem)]
                                border
                                border-white/20
                                bg-black/40
                                px-2.5
                                py-1.5
                                text-white
                                shadow-lg
                                shadow-black/10
                                backdrop-blur-xl
                            "
                        >
                            <span
                                aria-hidden="true"
                                className="mr-1.5"
                            >
                                {emoji}
                            </span>

                            <span className="truncate">
                                {categoryLabel}
                            </span>
                        </Badge>
                    </div>

                    {/* ========================================
                        TOP RIGHT — RATING
                    ======================================== */}
                    {hasRating && (
                        <div
                            className="
                                absolute
                                right-3.5
                                top-3.5
                                flex
                                max-w-[calc(100%-7rem)]
                                items-center
                                gap-1.5
                                rounded-full
                                border
                                border-white/20
                                bg-black/40
                                px-2.5
                                py-1.5
                                text-xs
                                font-semibold
                                text-white
                                shadow-lg
                                shadow-black/10
                                backdrop-blur-xl
                                sm:right-4
                                sm:top-4
                            "
                        >
                            <Star
                                className="h-3.5 w-3.5 shrink-0 fill-amber-400 text-amber-400"
                                aria-hidden="true"
                            />

                            <span>
                                {tour.averageRating?.toFixed(1)}
                            </span>

                            {tour.totalReviews > 0 && (
                                <span className="font-normal text-white/60">
                                    ({tour.totalReviews})
                                </span>
                            )}
                        </div>
                    )}

                    {/* ========================================
                        FEATURED
                    ======================================== */}
                    {tour.featured && (
                        <div className="absolute bottom-3.5 left-3.5 sm:bottom-4 sm:left-4">
                            <span
                                className="
                                    inline-flex
                                    max-w-[calc(100vw-2rem)]
                                    items-center
                                    rounded-full
                                    border
                                    border-white/20
                                    bg-expedition-clay/90
                                    px-3
                                    py-1.5
                                    text-[9px]
                                    font-bold
                                    uppercase
                                    tracking-[0.16em]
                                    text-white
                                    shadow-lg
                                    backdrop-blur-md
                                "
                            >
                                Featured journey
                            </span>
                        </div>
                    )}
                </div>

                {/* ========================================
                    CONTENT
                ======================================== */}
                <div className="flex min-w-0 flex-1 flex-col p-5 sm:p-6">
                    {/* Destination */}
                    <div className="flex min-w-0 items-center gap-1.5">
                        <MapPin
                            className="
                                h-3.5
                                w-3.5
                                shrink-0
                                text-accent
                            "
                            aria-hidden="true"
                        />

                        <p
                            className="
                                min-w-0
                                truncate
                                text-[10px]
                                font-semibold
                                uppercase
                                tracking-[0.14em]
                                text-muted-foreground
                            "
                        >
                            {tour.destination}
                        </p>
                    </div>

                    {/* Title */}
                    <h3
                        className="
                            mt-2.5
                            line-clamp-2
                            min-h-[3.25rem]
                            font-display
                            text-lg
                            font-semibold
                            leading-[1.35]
                            tracking-tight
                            text-foreground
                            transition-colors
                            duration-300
                            group-hover:text-accent
                            sm:text-xl
                        "
                    >
                        {tour.name}
                    </h3>

                    {/* Description */}
                    <div className="min-w-0">
                        {tour.shortDescription ? (
                            <p
                                className="
                                    mt-2.5
                                    line-clamp-2
                                    min-h-[3rem]
                                    text-sm
                                    leading-6
                                    text-muted-foreground
                                "
                            >
                                {tour.shortDescription}
                            </p>
                        ) : (
                            <div className="min-h-[3rem]" />
                        )}
                    </div>

                    {/* ========================================
                        METADATA
                    ======================================== */}
                    <div className="mt-4 flex min-w-0 flex-wrap gap-1.5">
                        <Badge
                            variant={DIFFICULTY_VARIANT[tour.difficulty]}
                            className="
                                max-w-full
                                truncate
                                px-2.5
                                py-1
                                text-[10px]
                                font-semibold
                                uppercase
                                tracking-wide
                            "
                        >
                            {DIFFICULTY_LABELS[tour.difficulty]}
                        </Badge>

                        <Badge
                            variant="outline"
                            className="
                                max-w-full
                                gap-1.5
                                truncate
                                px-2.5
                                py-1
                                text-[10px]
                                font-medium
                            "
                        >
                            <Clock3
                                className="h-3 w-3 shrink-0"
                                aria-hidden="true"
                            />

                            <span className="truncate">
                                {tour.formattedDuration}
                            </span>
                        </Badge>
                    </div>

                    {/* Divider */}
                    <div className="my-5 h-px bg-border/70" />

                    {/* ========================================
                        FOOTER
                    ======================================== */}
                    <div className="mt-auto flex min-w-0 items-end justify-between gap-4">
                        {/* Price */}
                        <div className="min-w-0">
                            <p
                                className="
                                    text-[9px]
                                    font-semibold
                                    uppercase
                                    tracking-[0.16em]
                                    text-muted-foreground
                                "
                            >
                                From
                            </p>

                            <p
                                className="
                                    mt-0.5
                                    truncate
                                    font-display
                                    text-xl
                                    font-semibold
                                    tracking-tight
                                    text-foreground
                                    sm:text-2xl
                                "
                            >
                                {tour.currency ?? "KES"}{" "}
                                {formattedPrice}
                            </p>

                            <p className="mt-0.5 text-[10px] text-muted-foreground">
                                per person
                            </p>
                        </div>

                        {/* Actions */}
                        <div className="flex shrink-0 items-center gap-2">
                            {tour.active && (
                                <div
                                    onClick={(e) => e.stopPropagation()}
                                    onKeyDown={(e) => e.stopPropagation()}
                                >
                                    <EnquiryModal tour={tour} source="tour-card-enquire" />
                                </div>
                            )}

                            {/* Explore */}
                            <span
                                className="
                                inline-flex
                                shrink-0
                                items-center
                                gap-1.5
                                rounded-full
                                border
                                border-border
                                bg-background
                                px-3
                                py-2
                                text-xs
                                font-semibold
                                text-foreground
                                shadow-sm
                                transition-all
                                duration-300
                                group-hover:border-accent/40
                                group-hover:bg-accent
                                group-hover:text-accent-foreground
                                group-hover:shadow-md
                                sm:px-4
                            "
                            >
                            <span className="hidden xs:inline">
                                Explore
                            </span>

                            <ArrowUpRight
                                className="
                                    h-3.5
                                    w-3.5
                                    transition-transform
                                    duration-300
                                    group-hover:translate-x-0.5
                                    group-hover:-translate-y-0.5
                                "
                                aria-hidden="true"
                            />
                        </span>
                        </div>
                    </div>
                </div>
            </div>
        </motion.article>
    );
}