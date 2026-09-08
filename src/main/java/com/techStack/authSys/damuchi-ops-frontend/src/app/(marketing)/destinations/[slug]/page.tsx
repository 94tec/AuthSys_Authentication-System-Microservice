import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { CategoryLandingPage } from "@/components/landing/category-landing-page";
import { DESTINATION_CONFIG } from "@/content/category-config";

export function generateStaticParams() {
    return Object.keys(DESTINATION_CONFIG).map((slug) => ({
        slug,
    }));
}

export function generateMetadata({
                                     params,
                                 }: {
    params: { slug: string };
}): Metadata {
    const config = DESTINATION_CONFIG[params.slug];

    if (!config) return {};

    return {
        title: `${config.title} | Damuchi Safaris`,
        description: config.description,
    };
}

export default function DestinationPage({
                                            params,
                                        }: {
    params: { slug: string };
}) {
    const config = DESTINATION_CONFIG[params.slug];

    if (!config) notFound();

    return (
        <CategoryLandingPage
            title={config.title}
            description={config.description}
            search={config.search}
        />
    );
}