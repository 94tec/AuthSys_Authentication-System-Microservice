"use client";

import { PremiumTourCarousel } from "./tour-carousel";
import type { TourSummary } from "@/types/tour";

interface Props {
    tours: TourSummary[];
}

export function TourShowcaseSection({
                                        tours,
                                    }: Props) {
    return (
        <section className="relative py-2">
            <div className="container mx-auto px-4">
                <PremiumTourCarousel
                    tours={tours}
                    title="Explore East Africa"
                    subtitle="Handpicked safaris, mountain adventures, cultural experiences and beach escapes."
                />
            </div>
        </section>
    );
}