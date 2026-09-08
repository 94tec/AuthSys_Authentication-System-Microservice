"use client";

import * as React from "react";
import useEmblaCarousel from "embla-carousel-react";
import {
    ChevronLeft,
    ChevronRight,
    ArrowRight,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { TourCard } from "./tour-card";
import type { TourSummary } from "@/types/tour";

interface PremiumTourCarouselProps {
    tours: TourSummary[];
    title?: string;
    subtitle?: string;
}

export function PremiumTourCarousel({
                                        tours,
                                        title = "Featured Safaris",
                                        subtitle = "Curated journeys across East Africa",
                                    }: PremiumTourCarouselProps) {
    const [selected, setSelected] = React.useState(0);

    const [emblaRef, emblaApi] = useEmblaCarousel({
        align: "start",
        dragFree: false,
        loop: true,
    });

    React.useEffect(() => {
        if (!emblaApi) return;

        const onSelect = () => {
            setSelected(emblaApi.selectedScrollSnap());
        };

        emblaApi.on("select", onSelect);

        onSelect();

        return () => {
            emblaApi.off("select", onSelect);
        };
    }, [emblaApi]);

    React.useEffect(() => {
        if (!emblaApi) return;

        const interval = setInterval(() => {
            emblaApi.scrollNext();
        }, 5500);

        return () => clearInterval(interval);
    }, [emblaApi]);

    return (
        <section
            className="
                relative
                overflow-hidden
                rounded-[36px]
                border
                border-white/10
                bg-white/[0.04]
                backdrop-blur-2xl
                shadow-[0_20px_80px_rgba(0,0,0,0.35)]
                p-8
              "
        >
            {/* Background Glow */}
            <div
                className="
                  absolute
                  inset-0
                  pointer-events-none
                  bg-[radial-gradient(circle_at_top_right,rgba(255,115,0,.15),transparent_35%),radial-gradient(circle_at_bottom_left,rgba(14,165,233,.15),transparent_35%)]
                "
            />

            {/* Header */}
            <div className="relative z-10 mb-8 flex items-center justify-between">
                <div>
                    <p
                        className="
                          text-xs
                          uppercase
                          tracking-[0.25em]
                          text-muted-foreground
                        "
                    >
                        Premium Collection
                    </p>

                    <h2 className="mt-2 text-3xl font-bold tracking-tight">
                        {title}
                    </h2>

                    <p className="mt-2 text-muted-foreground">
                        {subtitle}
                    </p>
                </div>

                <Button
                    variant="outline"
                    className="
                        hidden
                        md:flex
                        rounded-full
                        gap-2
                      "
                >
                    View All
                    <ArrowRight className="h-4 w-4" />
                </Button>
            </div>

            {/* Fade Edges */}
            <div className="pointer-events-none absolute left-0 top-0 z-10 h-full w-32 bg-gradient-to-r from-background to-transparent" />
            <div className="pointer-events-none absolute right-0 top-0 z-10 h-full w-32 bg-gradient-to-l from-background to-transparent" />

            {/* Carousel */}
            <div
                ref={emblaRef}
                className="overflow-hidden"
            >
                <div className="flex gap-6">
                    {tours.map((tour) => (
                        <div
                            key={tour.id}
                            className="
                min-w-0
                flex-[0_0_100%]

                sm:flex-[0_0_70%]

                lg:flex-[0_0_38%]

                xl:flex-[0_0_32%]
              "
                        >
                            <TourCard tour={tour} />
                        </div>
                    ))}
                </div>
            </div>

            {/* Dots */}
            <div className="mt-8 flex justify-center gap-2">
                {tours.map((_, index) => (
                    <button
                        key={index}
                        onClick={() => emblaApi?.scrollTo(index)}
                        className={`
              h-2 rounded-full transition-all duration-300
              ${
                            selected === index
                                ? "w-8 bg-primary"
                                : "w-2 bg-muted"
                        }
            `}
                    />
                ))}
            </div>
        </section>
    );
}