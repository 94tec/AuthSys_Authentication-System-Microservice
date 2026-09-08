import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { CategoryLandingPage } from "@/components/landing/category-landing-page";
import { HOTEL_CONFIG } from "@/content/category-config";

export function generateStaticParams() {
    return Object.keys(HOTEL_CONFIG).map((slug) => ({
        slug,
    }));
}

export function generateMetadata({
                                     params,
                                 }: {
    params: { slug: string };
}): Metadata {
    const config = HOTEL_CONFIG[params.slug];

    if (!config) return {};

    return {
        title: `${config.title} | Damuchi Safaris`,
        description: config.description,
    };
}

export default function HotelPage({
                                      params,
                                  }: {
    params: { slug: string };
}) {
    const config = HOTEL_CONFIG[params.slug];

    if (!config) notFound();

    return (
        <CategoryLandingPage
            title={config.title}
            description={config.description}
            search={config.search}
        />
    );
}