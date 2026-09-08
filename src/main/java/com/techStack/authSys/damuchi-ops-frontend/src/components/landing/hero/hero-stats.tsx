"use client";

import { motion } from "framer-motion";

const STATS = [
    { value: "15K+", label: "Travelers" },
    { value: "120+", label: "Curated Tours" },
    { value: "4.9★", label: "Guest Rating" },
];

export function HeroStats() {
    return (
        <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="mt-8 flex flex-wrap justify-center gap-4"
        >
            {STATS.map((stat) => (
                <div
                    key={stat.label}
                    className="
            rounded-2xl
            border border-white/10
            bg-white/5
            px-5 py-4
            backdrop-blur-xl
          "
                >
                    <p className="text-xl font-semibold text-expedition-sand">
                        {stat.value}
                    </p>

                    <p className="text-xs text-expedition-sand/60">
                        {stat.label}
                    </p>
                </div>
            ))}
        </motion.div>
    );
}