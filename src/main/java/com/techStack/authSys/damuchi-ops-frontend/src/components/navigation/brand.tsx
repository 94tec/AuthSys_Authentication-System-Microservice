"use client";

import Image from "next/image";
import Link from "next/link";
import { motion } from "framer-motion";

export function Brand() {
    return (
        <Link
            href="/"
            aria-label="Kivana Trails and Safaris home"
            className="group relative flex items-center gap-3"
        >
            <motion.div
                whileHover={{ scale: 1.05, rotate: -4 }}
                className="
                    flex h-12 w-12 shrink-0 items-center justify-center
                    overflow-hidden rounded-2xl
                    bg-white p-1
                    shadow-md ring-1 ring-border/60
                "
            >
                <Image
                    src="/images/kivana-logo.png"
                    alt="Kivana Trails and Safaris logo"
                    width={48}
                    height={48}
                    priority
                    className="h-full w-full object-contain"
                />
            </motion.div>

            <span className="font-display text-lg font-semibold tracking-tight">
                Kivana Trails &amp;
                <span className="ml-1 text-orange-500">Safaris</span>
            </span>
        </Link>
    );
}