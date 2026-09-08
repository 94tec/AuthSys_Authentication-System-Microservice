import {
    AlertCircle,
    CheckCircle2,
    Compass,
} from "lucide-react";

import { MarketingPage } from "@/components/marketing/marketing-page";

interface TravelContentPageProps {
    title: string;
    description: string;

    highlights?: string[];
    tips?: string[];
    warnings?: string[];
    children?: React.ReactNode;
}

export function TravelContentPage({
                                      title,
                                      description,
                                      highlights = [],
                                      tips = [],
                                      warnings = [],
                                      children,
                                  }: TravelContentPageProps) {
    return (
        <MarketingPage
            title={title}
            description={description}
            eyebrow="Travel Planning"
        >
            <div className="space-y-12">
                {highlights.length > 0 && (
                    <section>
                        <div className="mb-5 flex items-center gap-2">
                            <Compass className="h-5 w-5 text-accent" />
                            <h2 className="text-xl font-semibold">
                                Overview
                            </h2>
                        </div>

                        <div className="grid gap-4 sm:grid-cols-2">
                            {highlights.map((item) => (
                                <div
                                    key={item}
                                    className="rounded-2xl border bg-card p-5"
                                >
                                    {item}
                                </div>
                            ))}
                        </div>
                    </section>
                )}

                {tips.length > 0 && (
                    <section>
                        <div className="mb-5 flex items-center gap-2">
                            <CheckCircle2 className="h-5 w-5 text-green-600" />
                            <h2 className="text-xl font-semibold">
                                Helpful Tips
                            </h2>
                        </div>

                        <div className="space-y-3">
                            {tips.map((tip) => (
                                <div
                                    key={tip}
                                    className="rounded-xl border border-green-200 bg-green-50 p-4"
                                >
                                    {tip}
                                </div>
                            ))}
                        </div>
                    </section>
                )}

                {warnings.length > 0 && (
                    <section>
                        <div className="mb-5 flex items-center gap-2">
                            <AlertCircle className="h-5 w-5 text-amber-600" />
                            <h2 className="text-xl font-semibold">
                                Things To Know
                            </h2>
                        </div>

                        <div className="space-y-3">
                            {warnings.map((warning) => (
                                <div
                                    key={warning}
                                    className="rounded-xl border border-amber-200 bg-amber-50 p-4"
                                >
                                    {warning}
                                </div>
                            ))}
                        </div>
                    </section>
                )}

                {children}
            </div>
        </MarketingPage>
    );
}