"use client";

import Link from "next/link";
import { motion } from "framer-motion";

export function Brand() {
    return (
        <Link href="/" className="group relative flex items-center gap-4">
            <motion.div
                whileHover={{
                    scale: 1.05,
                    rotate: -4,
                }}
                className="
                    flex h-11 w-11 items-center justify-center
                    rounded-2xl
                    bg-gradient-to-br
                    from-amber-500
                    via-orange-500
                    to-amber-600
                    text-white
                    shadow-lg
                "
            >
                D
            </motion.div>

            <div>
                <h1 className="font-display text-lg font-semibold tracking-tight">
                    Damuchi
                    <span className="ml-1 text-orange-500">
                        Safaris
                    </span>
                </h1>
            </div>
        </Link>
    );
}