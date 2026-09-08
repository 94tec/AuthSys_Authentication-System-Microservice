"use client";

import {motion, useReducedMotion, Variants} from "framer-motion";
import {
    BadgeCheck,
    Quote,
    Star,
} from "lucide-react";

interface Testimonial {
    quote: string;
    name: string;
    location: string;
    initials: string;
    tour: string;
}

const TESTIMONIALS: Testimonial[] = [
    {
        quote:
            "The Diani dhow trip was pure magic — the crew made us feel like royalty, and the snorkeling was out of this world.",
        name: "Amina K.",
        location: "Nairobi, Kenya",
        initials: "AK",
        tour: "Coastal Dhow Safari",
    },
    {
        quote:
            "We trekked to see the gorillas in Volcanoes National Park and it changed how we see travel. Our guide's knowledge was incredible.",
        name: "James R.",
        location: "London, UK",
        initials: "JR",
        tour: "Rwanda Gorilla Trek",
    },
    {
        quote:
            "Seamless from booking to the Serengeti sunrise. No hidden fees, no confusing quotes — just a clear, beautiful trip.",
        name: "Sofia M.",
        location: "Cape Town, South Africa",
        initials: "SM",
        tour: "Serengeti Migration Safari",
    },
];

const containerVariants = {
    hidden: {},
    visible: {
        transition: {
            staggerChildren: 0.12,
        },
    },
};

const cardVariants: Variants = {
    hidden: {
        opacity: 0,
        y: 28,
    },
    visible: {
        opacity: 1,
        y: 0,
        transition: {
            duration: 0.55,
            ease: "easeOut",
        },
    },
};

export function Testimonials() {
    const reducedMotion = useReducedMotion();

    return (
        <section
            id="testimonials"
            aria-labelledby="testimonials-heading"
            className="relative overflow-hidden bg-coral/[0.035] py-20 sm:py-24"
        >
            {/* Atmospheric background */}
            <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0"
            >
                <div className="absolute left-1/2 top-0 h-72 w-72 -translate-x-1/2 rounded-full bg-coral/10 blur-3xl" />

                <div className="absolute -left-24 bottom-0 h-72 w-72 rounded-full bg-orange/10 blur-3xl" />

                <div className="absolute -right-24 top-1/3 h-80 w-80 rounded-full bg-amber-100/60 blur-3xl" />
            </div>

            <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
                {/* Header */}
                <motion.div
                    initial={reducedMotion ? false : { opacity: 0, y: 20 }}
                    whileInView={
                        reducedMotion
                            ? undefined
                            : { opacity: 1, y: 0 }
                    }
                    viewport={{ once: true, amount: 0.3 }}
                    transition={{ duration: 0.55 }}
                    className="mx-auto max-w-2xl text-center"
                >
                    <div className="inline-flex items-center gap-2 rounded-full border border-coral/10 bg-white/80 px-4 py-1.5 text-xs font-semibold uppercase tracking-[0.18em] text-coral shadow-sm backdrop-blur">
                        <Star className="h-3.5 w-3.5 fill-coral" />
                        Guest stories
                    </div>

                    <h2
                        id="testimonials-heading"
                        className="mt-5 font-display text-3xl font-bold tracking-tight text-gray-950 sm:text-4xl lg:text-5xl"
                    >
                        Journeys worth{" "}
                        <span className="text-coral">talking about.</span>
                    </h2>

                    <p className="mx-auto mt-4 max-w-xl text-sm leading-7 text-gray-600 sm:text-base">
                        Real stories from travelers who traded ordinary
                        holidays for unforgettable East African adventures.
                    </p>

                    {/* Rating summary */}
                    <div className="mt-6 inline-flex items-center gap-3 rounded-full border border-black/5 bg-white px-4 py-2 shadow-sm">
                        <div className="flex gap-0.5 text-amber-400">
                            {Array.from({ length: 5 }).map((_, index) => (
                                <Star
                                    key={index}
                                    className="h-3.5 w-3.5 fill-amber-400"
                                    aria-hidden="true"
                                />
                            ))}
                        </div>

                        <span className="h-4 w-px bg-gray-200" />

                        <span className="text-xs font-semibold text-gray-700">
                            4.9 / 5 guest rating
                        </span>
                    </div>
                </motion.div>

                {/* Testimonials */}
                <motion.div
                    variants={reducedMotion ? undefined : containerVariants}
                    initial={reducedMotion ? false : "hidden"}
                    whileInView={reducedMotion ? undefined : "visible"}
                    viewport={{ once: true, amount: 0.15 }}
                    className="mt-12 grid gap-6 md:grid-cols-2 lg:grid-cols-3"
                >
                    {TESTIMONIALS.map((testimonial) => (
                        <motion.article
                            key={testimonial.name}
                            variants={
                                reducedMotion ? undefined : cardVariants
                            }
                            whileHover={
                                reducedMotion
                                    ? undefined
                                    : {
                                          y: -7,
                                          transition: {
                                              duration: 0.2,
                                          },
                                      }
                            }
                            className="group relative flex h-full flex-col overflow-hidden rounded-[1.75rem] border border-black/[0.06] bg-white p-6 shadow-sm transition-shadow duration-300 hover:shadow-xl hover:shadow-black/[0.07] sm:p-7"
                        >
                            {/* Card glow */}
                            <div
                                aria-hidden="true"
                                className="pointer-events-none absolute -right-16 -top-16 h-32 w-32 rounded-full bg-coral/10 opacity-0 blur-2xl transition-opacity duration-500 group-hover:opacity-100"
                            />

                            {/* Quote icon */}
                            <div
                                aria-hidden="true"
                                className="absolute right-6 top-5 text-coral/[0.08] transition-transform duration-500 group-hover:scale-110 group-hover:text-coral/[0.12]"
                            >
                                <Quote className="h-4 w-4 fill-current" />
                            </div>

                            {/* Stars */}
                            <div className="relative flex items-center gap-0.5">
                                {Array.from({ length: 5 }).map((_, index) => (
                                    <Star
                                        key={index}
                                        className="h-4 w-4 fill-amber-400 text-amber-400"
                                        aria-hidden="true"
                                    />
                                ))}

                                <span className="ml-2 text-[11px] font-medium uppercase tracking-wider text-gray-400">
                                    Verified stay
                                </span>
                            </div>

                            {/* Quote */}
                            <blockquote className="relative mt-6 flex-1">
                                <p className="text-[15px] leading-7 text-gray-700">
                                    “{testimonial.quote}”
                                </p>
                            </blockquote>

                            {/* Divider */}
                            <div className="my-6 h-px bg-gradient-to-r from-transparent via-gray-200 to-transparent" />

                            {/* Guest */}
                            <div className="flex items-center gap-3">
                                <div className="relative shrink-0">
                                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-gradient-to-br from-coral via-orange to-amber-500 text-sm font-bold text-white shadow-md shadow-coral/20">
                                        {testimonial.initials}
                                    </div>

                                    <div className="absolute -bottom-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-white">
                                        <BadgeCheck className="h-3.5 w-3.5 fill-coral text-white" />
                                    </div>
                                </div>

                                <div className="min-w-0">
                                    <div className="text-sm font-bold text-gray-950">
                                        {testimonial.name}
                                    </div>

                                    <div className="mt-0.5 truncate text-xs text-gray-500">
                                        {testimonial.location}
                                    </div>

                                    <div className="mt-1 text-[11px] font-semibold uppercase tracking-wide text-coral">
                                        {testimonial.tour}
                                    </div>
                                </div>
                            </div>
                        </motion.article>
                    ))}
                </motion.div>

                {/* Bottom reassurance */}
                <motion.div
                    initial={reducedMotion ? false : { opacity: 0, y: 12 }}
                    whileInView={
                        reducedMotion
                            ? undefined
                            : { opacity: 1, y: 0 }
                    }
                    viewport={{ once: true, amount: 0.3 }}
                    transition={{ delay: 0.25, duration: 0.5 }}
                    className="mt-10 flex flex-col items-center justify-center gap-2 text-center sm:flex-row sm:gap-3"
                >
                    <div className="flex items-center gap-2 text-sm font-semibold text-gray-800">
                        <BadgeCheck className="h-4 w-4 text-coral" />
                        Trusted by adventurous travelers
                    </div>

                    <span className="hidden h-1 w-1 rounded-full bg-gray-300 sm:block" />

                    <p className="text-xs text-gray-500">
                        Your next story could be here.
                    </p>
                </motion.div>
            </div>
        </section>
    );
}
