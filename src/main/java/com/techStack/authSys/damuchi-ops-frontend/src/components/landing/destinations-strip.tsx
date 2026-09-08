"use client";

import { useMemo, useState } from "react";
import {
  Compass,
  MapPin,
  ArrowUpRight,
  Sparkles,
} from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";

import type { TourCategory } from "@/types/tour";

interface Destination {
  name: string;
  country: Country;
  tag: string;
  emoji: string;
  category: TourCategory;
  gradient: string;
  image: string;
}

const COUNTRIES = [
  "All",
  "Kenya",
  "Tanzania",
  "Uganda",
  "Rwanda",
] as const;

type CountryFilter = (typeof COUNTRIES)[number];
type Country = Exclude<CountryFilter, "All">;

const DESTINATIONS: Destination[] = [
  // ─────────────────────────────────────────────
  // KENYA
  // ─────────────────────────────────────────────
  {
    name: "Maasai Mara",
    country: "Kenya",
    tag: "Safari & Wildlife",
    emoji: "🦁",
    category: "SAFARI",
    gradient:
      "from-amber-950/95 via-black/35 to-expedition-forest/80",
    image:
      "https://images.unsplash.com/photo-1516426122078-c23e76319801?auto=format&fit=crop&w=1400&q=85",
  },
  {
    name: "Diani Beach",
    country: "Kenya",
    tag: "Beach & Coast",
    emoji: "🌊",
    category: "BEACH",
    gradient:
      "from-cyan-950/90 via-black/15 to-slate-950/80",
    image:
      "https://images.unsplash.com/photo-1544551763-46a013bb70d5?auto=format&fit=crop&w=1400&q=85",
  },
  {
    name: "Mount Kenya",
    country: "Kenya",
    tag: "Mountain & Trekking",
    emoji: "⛰️",
    category: "MOUNTAIN",
    gradient:
      "from-emerald-950/90 via-black/20 to-expedition-forest/90",
    image:
      "https://images.unsplash.com/photo-1464822759023-fed622ff2c3b?auto=format&fit=crop&w=1400&q=85",
  },
  {
    name: "Lamu Old Town",
    country: "Kenya",
    tag: "Cultural & Heritage",
    emoji: "🏛️",
    category: "CULTURAL",
    gradient:
      "from-orange-950/90 via-black/20 to-expedition-forest/90",
    image:
      "https://images.unsplash.com/photo-1516026672322-bc52d61a55d5?auto=format&fit=crop&w=1400&q=85",
  },

  // ─────────────────────────────────────────────
  // TANZANIA
  // ─────────────────────────────────────────────
  {
    name: "Serengeti",
    country: "Tanzania",
    tag: "Safari & Migration",
    emoji: "🐆",
    category: "SAFARI",
    gradient:
      "from-orange-950/95 via-black/25 to-expedition-forest/90",
    image:
      "https://images.unsplash.com/photo-1516426122078-c23e76319801?auto=format&fit=crop&w=1400&q=85",
  },
  {
    name: "Zanzibar",
    country: "Tanzania",
    tag: "Beach & Coast",
    emoji: "🏝️",
    category: "BEACH",
    gradient:
      "from-teal-950/90 via-black/10 to-slate-950/80",
    image:
      "https://images.unsplash.com/photo-1589394815804-964ed0be2eb5?auto=format&fit=crop&w=1400&q=85",
  },

  // ─────────────────────────────────────────────
  // UGANDA
  // ─────────────────────────────────────────────
  {
    name: "Bwindi Forest",
    country: "Uganda",
    tag: "Gorilla Trekking",
    emoji: "🦍",
    category: "MOUNTAIN",
    gradient:
      "from-green-950/95 via-black/20 to-expedition-forest/95",
    image:
      "https://images.unsplash.com/photo-1549366021-9f761d450615?auto=format&fit=crop&w=1400&q=85",
  },

  // ─────────────────────────────────────────────
  // RWANDA
  // ─────────────────────────────────────────────
  {
    name: "Volcanoes NP",
    country: "Rwanda",
    tag: "Gorilla Trekking",
    emoji: "🦍",
    category: "MOUNTAIN",
    gradient:
      "from-emerald-950/95 via-black/20 to-teal-950/90",
    image:
      "https://images.unsplash.com/photo-1516026672322-bc52d61a55d5?auto=format&fit=crop&w=1400&q=85",
  },
];

const COUNTRY_COUNTS = DESTINATIONS.reduce<Record<Country, number>>(
  (acc, destination) => {
    acc[destination.country] =
      (acc[destination.country] ?? 0) + 1;

    return acc;
  },
  {
    Kenya: 0,
    Tanzania: 0,
    Uganda: 0,
    Rwanda: 0,
  },
);

export function DestinationsStrip() {
  const [filter, setFilter] =
    useState<CountryFilter>("All");

  const shouldReduceMotion = useReducedMotion();

  const filteredDestinations = useMemo(() => {
    if (filter === "All") {
      return DESTINATIONS;
    }

    return DESTINATIONS.filter(
      (destination) =>
        destination.country === filter,
    );
  }, [filter]);

  function handleDestinationClick(
    destination: Destination,
  ) {
    const toursSection =
      document.getElementById("tours");

    toursSection?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });

    window.dispatchEvent(
      new CustomEvent("basecamp:search", {
        detail: {
          search: "",
          category: destination.category,
        },
      }),
    );
  }

  return (
    <section
      id="destinations"
      aria-labelledby="destinations-heading"
      className="relative overflow-hidden py-12 sm:py-16 lg:py-20"
    >
      {/* ═══════════════════════════════════════════
          AMBIENT BACKGROUND
      ═══════════════════════════════════════════ */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0"
      >
        <motion.div
          animate={
            shouldReduceMotion
              ? undefined
              : {
                  x: [0, 35, 0],
                  y: [0, -20, 0],
                }
          }
          transition={{
            duration: 12,
            repeat: Infinity,
            ease: "easeInOut",
          }}
          className="absolute left-[15%] top-0 h-72 w-72 rounded-full bg-expedition-clay/5 blur-3xl"
        />

        <motion.div
          animate={
            shouldReduceMotion
              ? undefined
              : {
                  x: [0, -30, 0],
                  y: [0, 25, 0],
                }
          }
          transition={{
            duration: 15,
            repeat: Infinity,
            ease: "easeInOut",
          }}
          className="absolute bottom-0 right-[5%] h-96 w-96 rounded-full bg-accent/5 blur-3xl"
        />
      </div>

      <div className="container relative">
        {/* ═══════════════════════════════════════════
            HEADER
        ═══════════════════════════════════════════ */}
        <motion.div
          initial={
            shouldReduceMotion
              ? false
              : {
                  opacity: 0,
                  y: 24,
                }
          }
          whileInView={
            shouldReduceMotion
              ? undefined
              : {
                  opacity: 1,
                  y: 0,
                }
          }
          viewport={{
            once: true,
            amount: 0.25,
          }}
          transition={{
            duration: 0.6,
            ease: "easeOut",
          }}
          className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between"
        >
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-accent/20 bg-accent/5 px-3 py-1.5">
              <Compass
                className="h-3.5 w-3.5 text-accent"
                aria-hidden="true"
              />

              <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-accent">
                Where to next
              </span>
            </div>

            <h2
              id="destinations-heading"
              className="mt-4 font-display text-3xl font-medium tracking-tight text-foreground sm:text-4xl lg:text-5xl"
            >
              Places that stay with you.
            </h2>

            <p className="mt-3 max-w-xl text-sm leading-7 text-muted-foreground sm:text-base">
              From the great plains of the Serengeti to
              the warm waters of the Indian Ocean, discover
              East Africa one extraordinary destination at a
              time.
            </p>
          </div>

          <div className="hidden shrink-0 text-right sm:block">
            <p className="font-display text-3xl font-semibold tracking-tight text-foreground">
              {DESTINATIONS.length}
            </p>

            <p className="text-xs uppercase tracking-[0.14em] text-muted-foreground">
              Featured destinations
            </p>
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════
            COUNTRY FILTERS
        ═══════════════════════════════════════════ */}
        <motion.div
          initial={
            shouldReduceMotion
              ? false
              : {
                  opacity: 0,
                  y: 10,
                }
          }
          whileInView={
            shouldReduceMotion
              ? undefined
              : {
                  opacity: 1,
                  y: 0,
                }
          }
          viewport={{
            once: true,
            amount: 0.15,
          }}
          transition={{
            duration: 0.45,
            delay: 0.08,
          }}
          className="mt-8"
        >
          <div
            className="flex flex-wrap gap-2"
            role="group"
            aria-label="Filter destinations by country"
          >
            {COUNTRIES.map((country) => {
              const isActive =
                filter === country;

              const count =
                country === "All"
                  ? DESTINATIONS.length
                  : COUNTRY_COUNTS[country];

              return (
                <motion.button
                  key={country}
                  type="button"
                  onClick={() =>
                    setFilter(country)
                  }
                  aria-pressed={isActive}
                  whileHover={
                    shouldReduceMotion
                      ? undefined
                      : {
                          y: -2,
                        }
                  }
                  whileTap={
                    shouldReduceMotion
                      ? undefined
                      : {
                          scale: 0.97,
                        }
                  }
                  className={[
                    "inline-flex items-center gap-2 rounded-full border px-4 py-2",
                    "text-xs font-semibold tracking-wide",
                    "transition-all duration-200",
                    "focus-visible:outline-none focus-visible:ring-2",
                    "focus-visible:ring-ring focus-visible:ring-offset-2",
                    isActive
                      ? "border-accent bg-accent text-accent-foreground shadow-sm shadow-accent/20"
                      : "border-border bg-background text-muted-foreground hover:border-accent/40 hover:bg-accent/5 hover:text-foreground",
                  ].join(" ")}
                >
                  {country}

                  <span
                    className={[
                      "rounded-full px-1.5 py-0.5 text-[9px]",
                      isActive
                        ? "bg-black/10"
                        : "bg-muted",
                    ].join(" ")}
                  >
                    {count}
                  </span>
                </motion.button>
              );
            })}
          </div>
        </motion.div>

        {/* ═══════════════════════════════════════════
            DESTINATION CARDS
        ═══════════════════════════════════════════ */}
        <motion.div
          layout
          className={[
            "mt-10 grid gap-4",
            "grid-cols-1 sm:grid-cols-2",
            "lg:grid-cols-4",
          ].join(" ")}
          role="list"
          aria-label="Featured destinations"
        >
          {filteredDestinations.map(
            (destination, index) => (
              <motion.button
                layout
                key={destination.name}
                type="button"
                role="listitem"
                onClick={() =>
                  handleDestinationClick(
                    destination,
                  )
                }
                initial={
                  shouldReduceMotion
                    ? false
                    : {
                        opacity: 0,
                        y: 30,
                        scale: 0.97,
                      }
                }
                whileInView={
                  shouldReduceMotion
                    ? undefined
                    : {
                        opacity: 1,
                        y: 0,
                        scale: 1,
                      }
                }
                viewport={{
                  once: true,
                  amount: 0.15,
                }}
                transition={{
                  duration: 0.55,
                  delay: Math.min(
                    index * 0.07,
                    0.35,
                  ),
                  ease: "easeOut",
                }}
                whileHover={
                  shouldReduceMotion
                    ? undefined
                    : {
                        y: -7,
                      }
                }
                whileTap={
                  shouldReduceMotion
                    ? undefined
                    : {
                        scale: 0.985,
                      }
                }
                aria-label={`Browse ${destination.tag} tours in ${destination.name}, ${destination.country}`}
                className={[
                  "group relative h-[380px] w-full",
                  "overflow-hidden rounded-3xl",
                  "text-left",
                  "bg-black",
                  "shadow-sm",
                  "transition-shadow duration-500",
                  "hover:shadow-2xl hover:shadow-black/20",
                  "focus-visible:outline-none",
                  "focus-visible:ring-2",
                  "focus-visible:ring-ring",
                  "focus-visible:ring-offset-2",
                ].join(" ")}
              >
                {/* ─────────────────────────────────
                    FULL-COVER IMAGE
                ───────────────────────────────── */}
                <div className="absolute inset-0 overflow-hidden">
                  <motion.img
                    src={destination.image}
                    alt=""
                    loading={
                      index < 4
                        ? "eager"
                        : "lazy"
                    }
                    animate={
                      shouldReduceMotion
                        ? undefined
                        : {
                            scale: [
                              1,
                              1.055,
                              1,
                            ],
                          }
                    }
                    transition={{
                      duration:
                        12 + index * 0.8,
                      repeat: Infinity,
                      ease: "easeInOut",
                      delay: index * 0.4,
                    }}
                    whileHover={
                      shouldReduceMotion
                        ? undefined
                        : {
                            scale: 1.12,
                          }
                    }
                    className={[
                      "h-full w-full",
                      "object-cover",
                      "object-center",
                      "transition-transform",
                      "duration-[1400ms]",
                      "ease-out",
                    ].join(" ")}
                  />

                  {/* Destination colour wash */}
                  <div
                    aria-hidden="true"
                    className={[
                      "absolute inset-0 bg-gradient-to-br",
                      destination.gradient,
                    ].join(" ")}
                  />

                  {/* Cinematic bottom gradient */}
                  <div
                    aria-hidden="true"
                    className="absolute inset-0 bg-gradient-to-t from-black via-black/35 to-transparent"
                  />

                  {/* Top vignette */}
                  <div
                    aria-hidden="true"
                    className="absolute inset-x-0 top-0 h-32 bg-gradient-to-b from-black/45 to-transparent"
                  />
                </div>

                {/* ─────────────────────────────────
                    ANIMATED LIGHT SWEEP
                ───────────────────────────────── */}
                <motion.div
                  aria-hidden="true"
                  animate={
                    shouldReduceMotion
                      ? undefined
                      : {
                          x: [
                            "-120%",
                            "180%",
                          ],
                        }
                  }
                  transition={{
                    duration: 7,
                    repeat: Infinity,
                    repeatDelay: 4,
                    ease: "easeInOut",
                  }}
                  className="pointer-events-none absolute inset-y-0 w-1/2 skew-x-[-18deg] bg-gradient-to-r from-transparent via-white/10 to-transparent"
                />

                {/* ─────────────────────────────────
                    BORDER / GLOW
                ───────────────────────────────── */}
                <div
                  aria-hidden="true"
                  className="absolute inset-0 rounded-3xl border border-white/10 transition-colors duration-500 group-hover:border-white/25"
                />

                {/* ─────────────────────────────────
                    TOP METADATA
                ───────────────────────────────── */}
                <div className="absolute left-4 right-4 top-4 flex items-center justify-between">
                  <motion.span
                    whileHover={
                      shouldReduceMotion
                        ? undefined
                        : {
                            scale: 1.04,
                          }
                    }
                    className="inline-flex items-center gap-1.5 rounded-full border border-white/15 bg-black/30 px-3 py-1.5 font-mono text-[9px] font-medium uppercase tracking-[0.12em] text-white/85 shadow-lg backdrop-blur-md"
                  >
                    <MapPin
                      className="h-3 w-3"
                      aria-hidden="true"
                    />

                    {destination.country}
                  </motion.span>

                  <motion.span
                    whileHover={
                      shouldReduceMotion
                        ? undefined
                        : {
                            rotate: 45,
                          }
                    }
                    className="flex h-10 w-10 items-center justify-center rounded-full border border-white/15 bg-black/30 text-white/80 shadow-lg backdrop-blur-md transition-all duration-300 group-hover:border-white/30 group-hover:bg-white group-hover:text-foreground"
                  >
                    <ArrowUpRight
                      className="h-4 w-4"
                      aria-hidden="true"
                    />
                  </motion.span>
                </div>

                {/* ─────────────────────────────────
                    BOTTOM CONTENT
                ───────────────────────────────── */}
                <div className="absolute inset-x-5 bottom-5">
                  <div className="flex items-end justify-between gap-4">
                    <div>
                      <motion.div
                        animate={
                          shouldReduceMotion
                            ? undefined
                            : {
                                y: [
                                  0,
                                  -4,
                                  0,
                                ],
                              }
                        }
                        transition={{
                          duration: 4,
                          repeat: Infinity,
                          ease: "easeInOut",
                          delay:
                            index * 0.2,
                        }}
                        className="mb-3 text-3xl drop-shadow-lg"
                        aria-hidden="true"
                      >
                        {destination.emoji}
                      </motion.div>

                      <p className="font-mono text-[9px] font-semibold uppercase tracking-[0.18em] text-white/65">
                        {destination.tag}
                      </p>

                      <h3 className="mt-1 font-display text-2xl font-medium tracking-tight text-white sm:text-[27px]">
                        {destination.name}
                      </h3>

                      <div className="mt-2 flex items-center gap-1.5 text-xs text-white/55 transition-colors duration-300 group-hover:text-white/85">
                        <span>
                          Explore journeys
                        </span>

                        <ArrowUpRight
                          className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                          aria-hidden="true"
                        />
                      </div>
                    </div>

                    {/* Floating category marker */}
                    <motion.div
                      aria-hidden="true"
                      animate={
                        shouldReduceMotion
                          ? undefined
                          : {
                              y: [0, -5, 0],
                            }
                      }
                      transition={{
                        duration: 3.5,
                        repeat: Infinity,
                        ease: "easeInOut",
                        delay:
                          index * 0.25,
                      }}
                      className="mb-1 hidden h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-white/10 text-white/70 backdrop-blur-md sm:flex"
                    >
                      <Sparkles className="h-4 w-4" />
                    </motion.div>
                  </div>
                </div>

                {/* ─────────────────────────────────
                    HOVER EDGE GLOW
                ───────────────────────────────── */}
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-0 rounded-3xl opacity-0 ring-1 ring-inset ring-white/30 transition-opacity duration-500 group-hover:opacity-100"
                />
              </motion.button>
            ),
          )}
        </motion.div>

        {/* ═══════════════════════════════════════════
            EMPTY STATE
        ═══════════════════════════════════════════ */}
        {filteredDestinations.length === 0 && (
          <motion.div
            initial={
              shouldReduceMotion
                ? false
                : {
                    opacity: 0,
                    y: 10,
                  }
            }
            animate={{
              opacity: 1,
              y: 0,
            }}
            className="mt-10 rounded-3xl border border-dashed border-border p-10 text-center"
          >
            <Compass
              className="mx-auto h-8 w-8 text-muted-foreground"
              aria-hidden="true"
            />

            <p className="mt-3 font-display text-lg font-medium">
              More destinations are coming.
            </p>

            <p className="mt-1 text-sm text-muted-foreground">
              We&apos;re always adding new places to
              explore.
            </p>
          </motion.div>
        )}

        {/* ═══════════════════════════════════════════
            MOBILE SWIPE HINT
        ═══════════════════════════════════════════ */}
        {filteredDestinations.length > 1 && (
          <div className="mt-4 flex items-center justify-center gap-2 text-[10px] uppercase tracking-[0.15em] text-muted-foreground sm:hidden">
            <span className="h-px w-6 bg-border" />
            Swipe to explore
            <span className="h-px w-6 bg-border" />
          </div>
        )}
      </div>
    </section>
  );
}

