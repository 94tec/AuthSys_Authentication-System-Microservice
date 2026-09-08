"use client";

import Link from "next/link";
import {
    ChevronRight,
    Compass,
    ShieldCheck,
    Star,
    Users,
} from "lucide-react";

import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { TourGrid } from "@/components/tours/tour-grid";
import { EnquiryModal } from "@/components/landing/enquiry/enquiry-modal";

import type { TourCategory } from "@/types/tour";

interface CategoryLandingPageProps {
    title: string;
    description: string;
    category?: TourCategory | null;
    search?: string;
}

export function CategoryLandingPage({
                                        title,
                                        description,
                                        category,
                                        search,
                                    }: CategoryLandingPageProps) {
    return (
        <div className="flex min-h-screen flex-col bg-background">
            <Navbar />

            <main className="flex-1">
                {/* Hero */}
                <section className="relative overflow-hidden border-b">
                    {/* Background */}
                    <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-slate-900 to-orange-950" />

                    {/* Glow */}
                    <div
                        aria-hidden="true"
                        className="
                            absolute
                            left-1/2 top-0
                            h-[500px]
                            w-[500px]
                            -translate-x-1/2
                            rounded-full
                            bg-orange-500/10
                            blur-3xl
                        "
                    />

                    {/* Texture */}
                    <div
                        aria-hidden="true"
                        className="absolute inset-0 opacity-[0.04]"
                        style={{
                            backgroundImage:
                                "radial-gradient(circle at center, white 1px, transparent 1px)",
                            backgroundSize: "28px 28px",
                        }}
                    />

                    <div className="container relative py-20 sm:py-24 lg:py-28">
                        {/* Breadcrumb */}
                        <div className="mb-6 flex items-center gap-2 text-xs text-white/50">
                            <Link
                                href="/"
                                className="transition hover:text-white"
                            >
                                Home
                            </Link>

                            <ChevronRight className="h-3 w-3" />

                            <span className="text-white/70">
                                {title}
                            </span>
                        </div>

                        <div className="mx-auto max-w-4xl text-center">
                            <div
                                className="
                                    inline-flex
                                    items-center
                                    gap-2
                                    rounded-full
                                    border
                                    border-white/10
                                    bg-white/5
                                    px-4
                                    py-1.5
                                    text-xs
                                    font-medium
                                    text-orange-300
                                    backdrop-blur-md
                                "
                            >
                                <Compass className="h-3.5 w-3.5" />
                                Curated East African Experiences
                            </div>

                            <h1
                                className="
                                    mt-6
                                    font-display
                                    text-4xl
                                    font-bold
                                    tracking-tight
                                    text-white
                                    sm:text-5xl
                                    lg:text-6xl
                                "
                            >
                                {title}
                            </h1>

                            <p
                                className="
                                    mx-auto
                                    mt-6
                                    max-w-2xl
                                    text-base
                                    leading-relaxed
                                    text-white/70
                                    sm:text-lg
                                "
                            >
                                {description}
                            </p>

                            <div
                                className="
                                    mt-10
                                    flex
                                    flex-wrap
                                    items-center
                                    justify-center
                                    gap-4
                                "
                            >
                                <EnquiryModal source="category-page-hero" />

                                <Link
                                    href="/register"
                                    className="
                                        inline-flex
                                        items-center
                                        justify-center
                                        rounded-full
                                        border
                                        border-white/10
                                        bg-white/5
                                        px-6
                                        py-3
                                        text-sm
                                        font-medium
                                        text-white
                                        backdrop-blur-md
                                        transition
                                        hover:bg-white/10
                                    "
                                >
                                    Create Account
                                </Link>
                            </div>
                        </div>

                        {/* Trust Strip */}
                        <div
                            className="
                                mx-auto
                                mt-14
                                grid
                                max-w-4xl
                                grid-cols-1
                                gap-4
                                rounded-3xl
                                border
                                border-white/10
                                bg-white/[0.04]
                                p-5
                                backdrop-blur-xl
                                sm:grid-cols-3
                            "
                        >
                            <div className="flex items-center gap-3">
                                <ShieldCheck className="h-5 w-5 text-orange-400" />

                                <div>
                                    <p className="text-sm text-white">
                                        Secure Booking
                                    </p>

                                    <p className="text-xs text-white/50">
                                        Safe payments & verified operators
                                    </p>
                                </div>
                            </div>

                            <div className="flex items-center gap-3">
                                <Star className="h-5 w-5 text-orange-400" />

                                <div>
                                    <p className="text-sm text-white">
                                        Top Rated Tours
                                    </p>

                                    <p className="text-xs text-white/50">
                                        Reviewed by travelers worldwide
                                    </p>
                                </div>
                            </div>

                            <div className="flex items-center gap-3">
                                <Users className="h-5 w-5 text-orange-400" />

                                <div>
                                    <p className="text-sm text-white">
                                        Local Experts
                                    </p>

                                    <p className="text-xs text-white/50">
                                        Guides who know every trail
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Tours */}
                <section className="relative">
                    <TourGrid
                        initialCategory={category}
                        initialSearch={search}
                    />
                </section>

                {/* Bottom CTA */}
                <section className="border-t bg-muted/30 py-16">
                    <div className="container text-center">
                        <h2 className="font-display text-3xl font-semibold">
                            Need help planning?
                        </h2>

                        <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
                            Tell us what you're looking for and our team will
                            recommend the perfect itinerary for your dates,
                            budget and travel style.
                        </p>

                        <div className="mt-8">
                            <EnquiryModal source="category-page-footer" />
                        </div>
                    </div>
                </section>
            </main>

            <Footer />
        </div>
    );
}