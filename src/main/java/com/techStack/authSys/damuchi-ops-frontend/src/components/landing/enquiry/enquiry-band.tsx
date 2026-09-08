"use client";

import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import {
    ArrowLeft,
    ArrowRight,
    CheckCircle2,
    ChevronDown,
    Compass,
    Loader2,
    MessageSquareText,
} from "lucide-react";

import { EnquiryForm } from "@/components/landing/enquiry/enquiry-form";
import { tourApi } from "@/lib/tour-api";
import type { TourSummary } from "@/types/tour";

export function EnquiryBand() {
    const reducedMotion = useReducedMotion();

    const [tours, setTours] = useState<TourSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedTour, setSelectedTour] =
        useState<TourSummary | null>(null);
    const [loadError, setLoadError] = useState(false);

    useEffect(() => {
        let mounted = true;

        const loadTours = async () => {
            try {
                setLoading(true);
                setLoadError(false);

                const data = await tourApi.getTours(0, 20);

                if (!mounted) return;

                setTours(data.content ?? []);
            } catch {
                if (!mounted) return;

                setTours([]);
                setLoadError(true);
            } finally {
                if (mounted) {
                    setLoading(false);
                }
            }
        };

        loadTours();

        return () => {
            mounted = false;
        };
    }, []);

    const handleTourChange = (
        event: React.ChangeEvent<HTMLSelectElement>,
    ) => {
        const tour = tours.find(
            (item) => item.id === event.target.value,
        );

        setSelectedTour(tour ?? null);
    };

    return (
        <section
            id="enquiry"
            aria-labelledby="enquiry-heading"
            className="relative overflow-hidden px-4 py-12 sm:px-6 sm:py-16 lg:px-8"
        >
            <motion.div
                initial={reducedMotion ? false : { opacity: 0, y: 24 }}
                whileInView={
                    reducedMotion
                        ? undefined
                        : { opacity: 1, y: 0 }
                }
                viewport={{ once: true, amount: 0.2 }}
                transition={{ duration: 0.65, ease: "easeOut" }}
                className="relative mx-auto max-w-7xl overflow-hidden rounded-[2rem] bg-gradient-to-br from-gray-950 via-[#102f3d] to-[#0b4657] shadow-2xl shadow-black/10"
            >
                {/* Atmospheric background */}
                <div
                    aria-hidden="true"
                    className="pointer-events-none absolute inset-0"
                >
                    <div className="absolute -right-32 -top-40 h-[28rem] w-[28rem] rounded-full bg-coral/15 blur-3xl" />

                    <div className="absolute -bottom-48 -left-32 h-[26rem] w-[26rem] rounded-full bg-orange/10 blur-3xl" />

                    <div className="absolute left-1/2 top-1/2 h-72 w-72 -translate-x-1/2 -translate-y-1/2 rounded-full bg-cyan-400/5 blur-3xl" />

                    <div className="absolute inset-0 opacity-[0.035] [background-image:linear-gradient(rgba(255,255,255,0.8)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.8)_1px,transparent_1px)] [background-size:48px_48px]" />
                </div>

                <div className="relative grid gap-10 p-7 sm:p-10 md:p-12 lg:grid-cols-[1fr_0.85fr] lg:items-center lg:gap-16 lg:p-16">
                    {/* ─────────────────────────
                        Copy
                    ───────────────────────── */}
                    <motion.div
                        initial={
                            reducedMotion
                                ? false
                                : { opacity: 0, x: -20 }
                        }
                        whileInView={
                            reducedMotion
                                ? undefined
                                : { opacity: 1, x: 0 }
                        }
                        viewport={{
                            once: true,
                            amount: 0.2,
                        }}
                        transition={{
                            duration: 0.55,
                            delay: 0.1,
                        }}
                    >
                        <div className="inline-flex items-center gap-2 rounded-full border border-orange/20 bg-orange/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-orange-300">
                            <MessageSquareText className="h-3.5 w-3.5" />
                            Start your journey
                        </div>

                        <h2
                            id="enquiry-heading"
                            className="mt-5 max-w-xl font-display text-3xl font-bold leading-tight tracking-tight text-white sm:text-4xl lg:text-2xl"
                        >
                            Your next great story{" "}
                            <span className="text-coral">
                                starts here.
                            </span>
                        </h2>

                        <p className="mt-5 max-w-xl text-sm leading-7 text-white/65 sm:text-base">
                            Tell us what you're dreaming about — Kenyan
                            coastlines, Tanzanian savannahs, Ugandan
                            rainforests, or Rwanda's volcanoes. We'll help
                            turn the idea into a journey worth remembering.
                        </p>

                        {/* Benefits */}
                        <div className="mt-7 grid gap-3 sm:grid-cols-3 lg:grid-cols-1 xl:grid-cols-3">
                            {[
                                "Response within 2 hours",
                                "No hidden fees",
                                "100% tailored",
                            ].map((item) => (
                                <div
                                    key={item}
                                    className="flex items-center gap-2.5 text-sm text-white/70"
                                >
                                    <CheckCircle2 className="h-4 w-4 shrink-0 text-coral" />
                                    <span>{item}</span>
                                </div>
                            ))}
                        </div>

                        {/* Small trust statement */}
                        <div className="mt-8 flex items-center gap-3 border-t border-white/10 pt-6">
                            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10">
                                <Compass className="h-4 w-4 text-coral" />
                            </div>

                            <div>
                                <p className="text-xs font-semibold text-white">
                                    Local knowledge. Personal service.
                                </p>
                                <p className="mt-0.5 text-[11px] text-white/45">
                                    East Africa, thoughtfully explored.
                                </p>
                            </div>
                        </div>
                    </motion.div>

                    {/* ─────────────────────────
                        Enquiry panel
                    ───────────────────────── */}
                    <motion.div
                        initial={
                            reducedMotion
                                ? false
                                : { opacity: 0, x: 20 }
                        }
                        whileInView={
                            reducedMotion
                                ? undefined
                                : { opacity: 1, x: 0 }
                        }
                        viewport={{
                            once: true,
                            amount: 0.2,
                        }}
                        transition={{
                            duration: 0.55,
                            delay: 0.2,
                        }}
                        className="relative"
                    >
                        {/* Panel glow */}
                        <div
                            aria-hidden="true"
                            className="absolute -inset-2 rounded-[2rem] bg-coral/10 blur-2xl"
                        />

                        <div className="relative rounded-[1.75rem] border border-white/10 bg-white/[0.07] p-5 shadow-2xl backdrop-blur-xl sm:p-7">
                            {loading ? (
                                <div
                                    className="flex min-h-[220px] flex-col items-center justify-center text-center"
                                    role="status"
                                    aria-live="polite"
                                >
                                    <div className="flex h-12 w-12 items-center justify-center rounded-full border border-white/10 bg-white/5">
                                        <Loader2 className="h-5 w-5 animate-spin text-coral" />
                                    </div>

                                    <p className="mt-4 text-sm font-medium text-white/75">
                                        Preparing available journeys…
                                    </p>

                                    <p className="mt-1 text-xs text-white/40">
                                        Just a moment.
                                    </p>
                                </div>
                            ) : selectedTour ? (
                                <div>
                                    <button
                                        type="button"
                                        onClick={() =>
                                            setSelectedTour(null)
                                        }
                                        className="group mb-5 inline-flex items-center gap-1.5 text-xs font-medium text-white/50 transition-colors hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-coral focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
                                    >
                                        <ArrowLeft className="h-3.5 w-3.5 transition-transform group-hover:-translate-x-0.5" />
                                        Choose a different journey
                                    </button>

                                    {/* Selected enquire-button.tsx */}
                                    <div className="mb-5 rounded-2xl border border-coral/20 bg-coral/[0.07] p-4">
                                        <div className="flex items-start gap-3">
                                            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-coral/10 text-coral">
                                                <Compass className="h-4 w-4" />
                                            </div>

                                            <div className="min-w-0">
                                                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-coral">
                                                    Your selected journey
                                                </p>

                                                <p className="mt-1 truncate text-sm font-semibold text-white">
                                                    {selectedTour.name}
                                                </p>

                                                <p className="mt-0.5 text-xs text-white/45">
                                                    {selectedTour.destination}
                                                </p>
                                            </div>
                                        </div>
                                    </div>

                                    <EnquiryForm
                                        tourId={selectedTour.id}
                                        tourName={selectedTour.name}
                                        source="landing-enquiry-band"
                                        onSuccess={() =>
                                            setSelectedTour(null)
                                        }
                                    />
                                </div>
                            ) : (
                                <div>
                                    <div>
                                        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-coral">
                                            Tell us where you're headed
                                        </p>

                                        <h3 className="mt-2 text-xl font-bold text-white">
                                            Choose your adventure
                                        </h3>

                                        <p className="mt-2 text-sm leading-6 text-white/50">
                                            Select a journey below and we'll
                                            help you plan the details.
                                        </p>
                                    </div>

                                    {loadError ? (
                                        <div className="mt-6 rounded-2xl border border-red-400/10 bg-red-400/5 p-5">
                                            <p className="text-sm font-medium text-white/80">
                                                We couldn't load the journeys
                                                right now.
                                            </p>

                                            <p className="mt-1 text-xs leading-5 text-white/40">
                                                Please try again shortly or
                                                explore the tours above.
                                            </p>
                                        </div>
                                    ) : tours.length === 0 ? (
                                        <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
                                            <div className="flex items-start gap-3">
                                                <Compass className="mt-0.5 h-4 w-4 shrink-0 text-coral" />

                                                <div>
                                                    <p className="text-sm font-medium text-white/80">
                                                        No journeys available
                                                        right now.
                                                    </p>

                                                    <p className="mt-1 text-xs leading-5 text-white/40">
                                                        Check back soon — we're
                                                        always adding new
                                                        adventures.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="mt-6">
                                            <label
                                                htmlFor="enquiry-tour"
                                                className="mb-2 block text-xs font-medium text-white/55"
                                            >
                                                Which tour interests you?
                                            </label>

                                            <div className="relative">
                                                <select
                                                    id="enquiry-tour"
                                                    value=""
                                                    onChange={
                                                        handleTourChange
                                                    }
                                                    className="w-full appearance-none rounded-2xl border border-white/10 bg-white/[0.06] px-4 py-3.5 pr-11 text-sm text-white outline-none transition-all placeholder:text-white/30 hover:border-white/20 focus:border-coral focus:bg-white/[0.09] focus:ring-2 focus:ring-coral/20"
                                                >
                                                    <option
                                                        value=""
                                                        disabled
                                                        className="bg-gray-950 text-gray-900"
                                                    >
                                                        Select a tour…
                                                    </option>

                                                    {tours.map((tour) => (
                                                        <option
                                                            key={tour.id}
                                                            value={tour.id}
                                                            className="bg-gray-950 text-white"
                                                        >
                                                            {tour.name} —{" "}
                                                            {
                                                                tour.destination
                                                            }
                                                        </option>
                                                    ))}
                                                </select>

                                                <ChevronDown
                                                    aria-hidden="true"
                                                    className="pointer-events-none absolute right-4 top-1/2 h-4 w-4 -translate-y-1/2 text-white/40"
                                                />
                                            </div>

                                            <div className="mt-5 flex items-center justify-between gap-4 rounded-2xl border border-white/5 bg-black/10 px-4 py-3">
                                                <div className="flex items-center gap-2">
                                                    <CheckCircle2 className="h-4 w-4 text-coral" />

                                                    <span className="text-xs text-white/50">
                                                        No obligation to book
                                                    </span>
                                                </div>

                                                <ArrowRight className="h-4 w-4 text-white/25" />
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </motion.div>
                </div>
            </motion.div>
        </section>
    );
}
