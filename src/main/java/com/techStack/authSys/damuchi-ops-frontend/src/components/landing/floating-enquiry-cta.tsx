"use client";

import { useEffect, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import Link from "next/link";
import { ArrowRight, PhoneCall } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useVisitorContext } from "./visitor-provider";

export function FloatingEnquiryCta() {
    const { status } = useVisitorContext();
    const reducedMotion = useReducedMotion();

    const [visible, setVisible] = useState(false);

    useEffect(() => {
        const handleScroll = () => {
            setVisible(window.scrollY > 400);
        };

        handleScroll();

        window.addEventListener("scroll", handleScroll, {
            passive: true,
        });

        return () => {
            window.removeEventListener("scroll", handleScroll);
        };
    }, []);

    // Don't show the public floating CTA while visitor
    // state is being resolved or for authenticated users.
    if (
        status === "loading" ||
        status === "customer" ||
        status === "staff"
    ) {
        return null;
    }

    return (
        <motion.div
            initial={false}
            animate={{
                opacity: visible ? 1 : 0,
                y: visible ? 0 : 24,
            }}
            transition={
                reducedMotion
                    ? { duration: 0 }
                    : {
                          duration: 0.3,
                          ease: "easeOut",
                      }
            }
            className={`fixed inset-x-4 bottom-4 z-40 sm:hidden ${
              visible
                  ? "pointer-events-auto"
                  : "pointer-events-none"
            }`}
            aria-hidden={!visible}
        >
            <div className="relative overflow-hidden rounded-full border border-black/[0.06] bg-white/95 p-1.5 pl-4 shadow-2xl shadow-black/15 backdrop-blur-xl">
                {/* Subtle atmospheric accent */}
                <div
                    aria-hidden="true"
                    className="pointer-events-none absolute -right-10 -top-10 h-20 w-20 rounded-full bg-coral/10 blur-2xl"
                />

                <div className="relative flex items-center justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-2.5">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-coral/10">
                            <PhoneCall
                                className="h-3.5 w-3.5 text-coral"
                                aria-hidden="true"
                            />
                        </div>

                        <div className="min-w-0">
                            <p className="text-xs font-semibold text-gray-950">
                                Ready to explore?
                            </p>

                            <p className="text-[10px] text-gray-500">
                                Let's plan your journey
                            </p>
                        </div>
                    </div>

                    <Link
                        href="/enquiries"
                        className="shrink-0"
                        tabIndex={visible ? 0 : -1}
                    >
                        <Button
                            variant="accent"
                            size="sm"
                            className="rounded-full px-4 shadow-sm shadow-coral/20"
                        >
                            Enquire
                            <ArrowRight
                                className="ml-1 h-3.5 w-3.5"
                                aria-hidden="true"
                            />
                        </Button>
                    </Link>
                </div>
            </div>
        </motion.div>
    );
}
