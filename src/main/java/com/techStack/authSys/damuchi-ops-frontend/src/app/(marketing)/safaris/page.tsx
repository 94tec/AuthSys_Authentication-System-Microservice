import type { Metadata } from "next";
import { CategoryLandingPage } from "@/components/landing/category-landing-page";

export const metadata: Metadata = {
    title: "East Africa Safaris | Damuchi Safaris",
    description:
        "Discover luxury, family, honeymoon, and wildlife safaris across Kenya, Tanzania, Uganda, and Rwanda.",
};

export default function SafarisPage() {
    return (
        <CategoryLandingPage
            title="East Africa Safaris"
            description="From the Maasai Mara to the Serengeti and Bwindi Forest, explore unforgettable safari adventures across East Africa."
            category="SAFARI"
        />
    );
}