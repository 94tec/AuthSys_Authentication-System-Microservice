"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import {
    ArrowRight,
    Heart,
    MessagesSquare,
    Compass,
} from "lucide-react";

import { useVisitorContext } from "./visitor-provider";

function ActionCard({
                        href,
                        title,
                        subtitle,
                        icon: Icon,
                    }: {
    href: string;
    title: string;
    subtitle: string;
    icon: React.ElementType;
}) {
    return (
        <motion.div
            whileHover={{
                y: -4,
                scale: 1.02,
            }}
            whileTap={{
                scale: 0.98,
            }}
        >
            <Link
                href={href}
                className="
                    flex min-w-[170px]
                    items-center gap-3
                    rounded-2xl
                    border
                    bg-background/80
                    px-4
                    py-3
                    backdrop-blur-xl
                    transition-all
                    hover:shadow-lg
                "
            >
                <div
                    className="
                        flex h-10 w-10
                        items-center justify-center
                        rounded-xl
                        bg-gradient-to-br
                        from-amber-500
                        to-orange-500
                        text-white
                    "
                >
                    <Icon className="h-5 w-5" />
                </div>

                <div>
                    <p className="text-sm font-semibold">
                        {title}
                    </p>

                    <p className="text-xs text-muted-foreground">
                        {subtitle}
                    </p>
                </div>
            </Link>
        </motion.div>
    );
}

export function WelcomeBackBand() {
    const { status, user } = useVisitorContext();

    if (status !== "customer") {
        return null;
    }

    const firstName =
        user?.displayName ||
        user?.email?.split("@")[0] ||
        "Traveler";

    const initials =
        firstName.charAt(0).toUpperCase();

    const hour = new Date().getHours();

    const greeting =
        hour < 12
            ? "Good Morning"
            : hour < 18
                ? "Good Afternoon"
                : "Good Evening";

    return (
        <section className="relative overflow-hidden">
            {/* Background Glow */}
            <div
                className="
                    absolute inset-0
                    bg-gradient-to-r
                    from-amber-500/10
                    via-orange-500/5
                    to-transparent
                    blur-3xl
                "
            />

            <div className="relative mx-auto max-w-7xl px-4 py-8 lg:px-8">
                <div
                    className="
                        rounded-3xl
                        border
                        bg-background/70
                        p-6
                        backdrop-blur-2xl
                        shadow-[0_10px_40px_rgba(0,0,0,.06)]
                    "
                >
                    <div
                        className="
                            flex flex-col gap-6
                            lg:flex-row
                            lg:items-center
                            lg:justify-between
                        "
                    >
                        {/* User Section */}
                        <div className="flex items-center gap-4">
                            <div
                                className="
                                    flex h-14 w-14
                                    items-center justify-center
                                    rounded-2xl
                                    bg-gradient-to-br
                                    from-amber-500
                                    via-orange-500
                                    to-amber-600
                                    text-lg
                                    font-bold
                                    text-white
                                    shadow-lg
                                "
                            >
                                {initials}
                            </div>

                            <div>
                                <p className="text-sm text-muted-foreground">
                                    {greeting},
                                </p>

                                <h2
                                    className="
                                        font-display
                                        text-0.5xl
                                        font-semibold
                                    "
                                >
                                    {firstName} 👋
                                </h2>

                                <p className="mt-1 text-sm text-muted-foreground">
                                    Ready for your next East African adventure?
                                </p>
                            </div>
                        </div>

                        {/* Actions */}
                        <div
                            className="
                                flex flex-col gap-3
                                sm:flex-row
                            "
                        >
                            <ActionCard
                                href="/enquiries-overview"
                                title="My Enquiries"
                                subtitle="Track requests"
                                icon={MessagesSquare}
                            />

                            <ActionCard
                                href="/wishlist"
                                title="Saved Tours"
                                subtitle="Your wishlist"
                                icon={Heart}
                            />

                            <motion.div
                                whileHover={{
                                    scale: 1.03,
                                }}
                                whileTap={{
                                    scale: 0.98,
                                }}
                            >
                                <Link
                                    href="/safaris"
                                    className="
                                        flex h-full
                                        items-center gap-2
                                        rounded-2xl
                                        bg-gradient-to-r
                                        from-amber-500
                                        to-orange-500
                                        px-6
                                        py-3
                                        font-medium
                                        text-white
                                        shadow-lg
                                    "
                                >
                                    <Compass className="h-4 w-4" />
                                    Discover Safaris
                                    <ArrowRight className="h-4 w-4" />
                                </Link>
                            </motion.div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    );
}