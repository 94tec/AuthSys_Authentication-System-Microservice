import type { Metadata } from "next";
import { CategoryLandingPage } from "@/components/landing/category-landing-page";

export const metadata: Metadata = {
    title: "Destinations | Damuchi Safaris",
    description:
        "Explore iconic destinations across Kenya, Tanzania, Uganda, and Rwanda.",
};

export default function DestinationsPage() {
    return (
        <CategoryLandingPage
            title="Explore Destinations"
            description="Wildlife safaris, tropical beaches, mountain adventures, and cultural discoveries across East Africa."
        />
    );
}