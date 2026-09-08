import type { Metadata } from "next";
import { CategoryLandingPage } from "@/components/landing/category-landing-page";

export const metadata: Metadata = {
    title: "Hotels & Lodges | Damuchi Safaris",
    description:
        "Beach resorts, safari lodges, luxury camps, and city hotels across East Africa.",
};

export default function HotelsPage() {
    return (
        <CategoryLandingPage
            title="Hotels & Lodges"
            description="Find handpicked beach resorts, safari lodges, luxury camps, and city stays throughout East Africa."
            search="hotel"
        />
    );
}