import Link from "next/link";

import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { CtaBandGate } from "@/components/landing/cta-band-gate";

interface MarketingPageProps {
    title: string;
    description: string;
    eyebrow?: string;
    children?: React.ReactNode;
}

export function MarketingPage({
                                  title,
                                  description,
                                  eyebrow = "Damuchi Safaris",
                                  children,
                              }: MarketingPageProps) {
    return (
        <div className="flex min-h-screen flex-col bg-background">
            <Navbar />

            <main className="flex-1">
                {/* Hero */}
                <section className="relative overflow-hidden border-b bg-gray-950 py-20 text-white sm:py-28">
                    <div
                        aria-hidden="true"
                        className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(245,158,11,0.18),transparent_40%)]"
                    />

                    <div className="container relative">
                        <nav
                            aria-label="Breadcrumb"
                            className="mb-6 text-sm text-white/50"
                        >
                            <Link
                                href="/"
                                className="hover:text-white"
                            >
                                Home
                            </Link>
                            <span className="mx-2">/</span>
                            <span>{title}</span>
                        </nav>

                        <p className="font-mono text-xs uppercase tracking-[0.18em] text-amber-400">
                            {eyebrow}
                        </p>

                        <h1 className="mt-3 max-w-4xl font-display text-4xl font-semibold tracking-tight sm:text-5xl lg:text-6xl">
                            {title}
                        </h1>

                        <p className="mt-5 max-w-2xl text-base leading-8 text-white/70">
                            {description}
                        </p>
                    </div>
                </section>

                {/* Content */}
                <section className="container py-16 sm:py-20">
                    <div className="mx-auto max-w-4xl">
                        {children}
                    </div>
                </section>

                <CtaBandGate />
            </main>

            <Footer />
        </div>
    );
}