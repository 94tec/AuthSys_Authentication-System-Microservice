"use client";

import { motion } from "framer-motion";
import { ChevronDown } from "lucide-react";

export function ScrollIndicator() {
    return (
        <motion.div
            animate={{ y: [0, 8, 0] }}
            transition={{
                duration: 2,
                repeat: Infinity,
            }}
            className="mt-12 flex justify-center"
        >
            <button
                onClick={() =>
                    document
                        .getElementById("tours")
                        ?.scrollIntoView({
                            behavior: "smooth",
                        })
                }
                className="
          flex flex-col
          items-center gap-2
          text-expedition-sand/50
        "
            >
        <span className="text-xs uppercase tracking-widest">
          Discover Tours
        </span>

                <ChevronDown className="h-5 w-5" />
            </button>
        </motion.div>
    );
}