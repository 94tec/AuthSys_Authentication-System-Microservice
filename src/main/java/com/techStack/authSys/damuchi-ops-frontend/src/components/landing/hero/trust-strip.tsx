"use client";

import {
    ShieldCheck,
    CreditCard,
    Headphones,
    BadgeCheck,
} from "lucide-react";

const ITEMS = [
    {
        icon: BadgeCheck,
        title: "Trusted Operators",
        description: "Verified travel partners",
    },
    {
        icon: CreditCard,
        title: "Secure Payments",
        description: "M-Pesa & card payments",
    },
    {
        icon: ShieldCheck,
        title: "Instant Confirmation",
        description: "Book with confidence",
    },
    {
        icon: Headphones,
        title: "24/7 Support",
        description: "We're here when you need us",
    },
];

export function TrustStrip() {
    return (
        <section
            aria-label="Why book with us"
            className="mt-12 w-full"
        >
            {/* Heading */}
            <div className="mb-5 text-center">
                <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-expedition-sand/45">
                    Why book with us
                </p>
            </div>

            {/* Trust Items */}
            <div className="flex flex-wrap justify-center gap-3">
                {ITEMS.map((item) => {
                    const Icon = item.icon;

                    return (
                        <div
                            key={item.title}
                            className="
                                group
                                flex items-center gap-3
                                rounded-2xl
                                border border-white/10
                                bg-white/[0.04]
                                px-4 py-3
                                backdrop-blur-sm
                                transition-all duration-300
                                hover:border-white/15
                                hover:bg-white/[0.07]
                            "
                        >
                            {/* Icon */}
                            <div
                                className="
                                    flex h-9 w-9 shrink-0
                                    items-center justify-center
                                    rounded-xl
                                    border border-white/10
                                    bg-white/[0.06]
                                    text-expedition-sand
                                    transition-transform duration-300
                                    group-hover:scale-105
                                "
                            >
                                <Icon className="h-4 w-4" strokeWidth={1.8} />
                            </div>

                            {/* Text */}
                            <div className="min-w-0">
                                <p className="text-xs font-semibold leading-tight text-expedition-sand/90">
                                    {item.title}
                                </p>

                                <p className="mt-0.5 text-[10px] leading-tight text-expedition-sand/45">
                                    {item.description}
                                </p>
                            </div>
                        </div>
                    );
                })}
            </div>
        </section>
    );
}

