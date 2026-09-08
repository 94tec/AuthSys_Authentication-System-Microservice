import type { Metadata } from "next";
import { CategoryLandingPage } from "@/components/landing/category-landing-page";

export const metadata: Metadata = {
    title: "Experiences & Activities | Damuchi Safaris",
    description:
        "Cultural tours, city experiences, trekking adventures, and unforgettable activities across East Africa.",
};

export default function ExperiencesPage() {
    return (
        <CategoryLandingPage
            title="Experiences & Activities"
            description="Discover curated cultural experiences, trekking adventures, day trips, and local encounters."
        />
    );
}