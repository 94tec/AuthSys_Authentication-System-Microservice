"use client";

import { useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import {
  ArrowRight,
  Compass,
  MapPin,
  Sparkles,
} from "lucide-react";

import { HeroSearch } from "./hero-search";
import { HeroStats } from "./hero-stats";
import { PopularSearches } from "./popular-searches";
import { TrustStrip } from "./trust-strip";
import { ScrollIndicator } from "./scroll-indicator";

const DESTINATIONS = [
  {
    name: "Kenya",
    eyebrow: "Wild · Coastal · Iconic",
    description: "Mara landscapes, wildlife and the Indian Ocean.",
    image:
      "https://images.unsplash.com/photo-1516426122078-c23e76319801?auto=format&fit=crop&w=1200&q=85",
    href: "/destinations/kenya",
  },
  {
    name: "Tanzania",
    eyebrow: "Safari · Wilderness",
    description: "Serengeti plains, Ngorongoro and Zanzibar.",
    image:
      "https://unsplash.com/photos/a-group-of-giraffe-standing-next-to-each-other-on-a-lush-green-field-OZNe5jzwKnw",
    href: "/destinations/tanzania",
  },
  {
    name: "Uganda",
    eyebrow: "Gorillas · Adventure",
    description: "Rainforests, gorillas and extraordinary encounters.",
    image:
      "https://images.unsplash.com/photo-1549366021-9f761d450615?auto=format&fit=crop&w=1200&q=85",
    href: "/destinations/uganda",
  },
  {
    name: "Rwanda",
    eyebrow: "Gorillas · Highlands",
    description: "Mountain landscapes and intimate wildlife journeys.",
    image:
      "https://images.unsplash.com/photo-1609198092458-38a293c7ac4b?auto=format&fit=crop&w=1200&q=85",
    href: "/destinations/rwanda",
  },
  {
    name: "East African Coast",
    eyebrow: "Beach · Escape",
    description: "Diani, Zanzibar and tropical Indian Ocean escapes.",
    image:
      "https://images.unsplash.com/photo-1548013146-72479768bada?auto=format&fit=crop&w=1200&q=85",
    href: "/destinations",
  },
];

export function Hero() {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const shouldReduceMotion = useReducedMotion();

  function handleSearch() {
    document.getElementById("tours")?.scrollIntoView({
      behavior: "smooth",
    });

    window.dispatchEvent(
      new CustomEvent("basecamp:search", {
        detail: {
          search: search.trim(),
          category,
        },
      }),
    );
  }

  return (
    <section className="relative overflow-hidden bg-expedition-forest">
      {/* ============================================================
          BACKGROUND ATMOSPHERE
      ============================================================ */}

      <div className="pointer-events-none absolute inset-0">
        {/* warm horizon glow */}
        <div className="absolute -top-40 left-1/2 h-[520px] w-[900px] -translate-x-1/2 rounded-full bg-amber-500/[0.09] blur-[130px]" />

        {/* side glow */}
        <div className="absolute -right-40 top-1/3 h-[420px] w-[420px] rounded-full bg-orange-400/[0.06] blur-[120px]" />

        {/* subtle architectural grid */}
        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{
            backgroundImage: `
linear-gradient(rgba(255,255,255,.5) 1px, transparent 1px),
linear-gradient(90deg, rgba(255,255,255,.5) 1px, transparent 1px)
`,
            backgroundSize: "72px 72px",
          }}
        />

        {/* vignette */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_15%,rgba(0,0,0,.22)_100%)]" />
      </div>

      <div className="container relative px-4 pb-12 pt-8 sm:px-6 lg:pb-16 lg:pt-12">
        {/* ============================================================
            HERO INTRO
        ============================================================ */}

        <motion.div
          initial={{ opacity: 0, y: shouldReduceMotion ? 0 : 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: "easeOut" }}
          className="mx-auto max-w-4xl text-center"
        >
          {/* eyebrow */}
          <div className="inline-flex items-center gap-2 rounded-full border border-amber-200/10 bg-white/[0.04] px-4 py-2 backdrop-blur-sm">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-300 opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-300" />
            </span>

            <span className="font-mono text-[10px] font-medium uppercase tracking-[0.28em] text-amber-300 sm:text-xs">
              DAMUCHI SAFARIS · EAST AFRICA
            </span>
          </div>

          {/* headline */}
          <h1
            className="
              mx-auto
              mt-6
              max-w-4xl
              font-display
              text-4xl
              font-semibold
              leading-[0.98]
              tracking-[-0.03em]
              text-expedition-sand
              sm:text-5xl
              md:text-6xl
              lg:text-7xl
            "
          >
            Extraordinary journeys.
            <br />

            <span className="text-amber-300">
              Wildly yours.
            </span>
          </h1>

          <p
            className="
              mx-auto
              mt-6
              max-w-2xl
              text-base
              leading-7
              text-expedition-sand/70
              sm:text-lg
            "
          >
            Discover Kenya, Tanzania, Uganda and Rwanda through
            thoughtfully planned safaris, coastal escapes and
            unforgettable local experiences.
          </p>

          {/* small value proposition */}
          <div className="mt-6 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-xs text-expedition-sand/50">
            <span className="inline-flex items-center gap-1.5">
              <Compass className="h-3.5 w-3.5 text-amber-300/80" />
              Local expertise
            </span>

            <span className="hidden h-1 w-1 rounded-full bg-white/20 sm:block" />

            <span className="inline-flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5 text-amber-300/80" />
              Personalised journeys
            </span>

            <span className="hidden h-1 w-1 rounded-full bg-white/20 sm:block" />

            <span className="inline-flex items-center gap-1.5">
              <MapPin className="h-3.5 w-3.5 text-amber-300/80" />
              East Africa specialists
            </span>
          </div>
        </motion.div>

        {/* ============================================================
            SEARCH / DISCOVERY
        ============================================================ */}

        <motion.div
          initial={{ opacity: 0, y: shouldReduceMotion ? 0 : 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{
            duration: 0.6,
            delay: 0.15,
            ease: "easeOut",
          }}
          className="mx-auto mt-9 max-w-5xl"
        >
          <HeroSearch
            search={search}
            category={category}
            onSearchChange={setSearch}
            onCategoryChange={setCategory}
            onSearch={handleSearch}
          />

          <PopularSearches onSelect={setSearch} />
        </motion.div>

        {/* ============================================================
            DESTINATION VISUAL DISCOVERY
        ============================================================ */}

        <motion.div
          initial={{ opacity: 0, y: shouldReduceMotion ? 0 : 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{
            duration: 0.7,
            delay: 0.25,
            ease: "easeOut",
          }}
          className="mx-auto mt-12 max-w-7xl"
        >
          {/* section heading */}
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-amber-300/80">
                Start exploring
              </p>

              <h2 className="mt-1 font-display text-xl font-medium text-expedition-sand sm:text-2xl">
                Where will Africa take you?
              </h2>
            </div>

            <a
              href="/destinations"
              className="
                hidden
                items-center
                gap-1.5
                text-xs
                font-medium
                text-expedition-sand/60
                transition-colors
                hover:text-amber-300
                sm:inline-flex
              "
            >
              View all destinations
              <ArrowRight className="h-3.5 w-3.5" />
            </a>
          </div>

          {/* ========================================================
              IMAGE GRID

              Desktop:
              [ Kenya large ] [ Tanzania ] [ Uganda ]
              [ Kenya large ] [ Rwanda    ] [ Coast ]

              Mobile:
              horizontal scroll / compact cards
          ======================================================== */}

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-12 lg:grid-rows-2">
            {DESTINATIONS.map((destination, index) => {
              const isFeatured = index === 0;

              return (
                <motion.a
                  key={destination.name}
                  href={destination.href}
                  whileHover={
                    shouldReduceMotion
                      ? undefined
                      : {
                          y: -4,
                        }
                  }
                  transition={{
                    duration: 0.25,
                    ease: "easeOut",
                  }}
                  className={`
                    group
                    relative
                    min-h-[220px]
                    overflow-hidden
                    rounded-2xl
                    border
                    border-white/[0.08]
                    bg-white/[0.03]
                    shadow-2xl
                    ${isFeatured
                        ? "sm:col-span-2 lg:col-span-6 lg:row-span-2 lg:min-h-[460px]"
                        : "lg:col-span-3 lg:min-h-[223px]"}
                  `}
                >
                  {/* image */}
                  <img
                    src={destination.image}
                    alt={`${destination.name} safari destination`}
                    loading={index === 0 ? "eager" : "lazy"}
                    className="
                      absolute
                      inset-0
                      h-full
                      w-full
                      object-cover
                      transition-transform
                      duration-700
                      ease-out
                      group-hover:scale-[1.06]
                    "
                  />

                  {/* image treatment */}
                  <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-black/15 to-black/5" />

                  <div className="absolute inset-0 bg-gradient-to-br from-black/20 via-transparent to-amber-900/10 opacity-70" />

                  {/* destination content */}
                  <div className="absolute inset-x-0 bottom-0 p-5 sm:p-6">
                    <div className="flex items-end justify-between gap-4">
                      <div>
                        <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-amber-300/90">
                          {destination.eyebrow}
                        </p>

                        <h3
                          className={`
                            mt-1
                            font-display
                            font-medium
                            text-expedition-sand
                            ${isFeatured ? "text-3xl sm:text-4xl" : "text-2xl"}
                            `}
                        >
                          {destination.name}
                        </h3>

                        <p
                          className={`
                            mt-1.5
                            max-w-sm
                            text-xs
                            leading-5
                            text-white/65
                            ${isFeatured ? "sm:text-sm" : ""}
                            `}
                        >
                          {destination.description}
                        </p>
                      </div>

                      <span
                        className="
                          flex
                          h-9
                          w-9
                          shrink-0
                          translate-y-1
                          items-center
                          justify-center
                          rounded-full
                          border
                          border-white/20
                          bg-white/10
                          text-white
                          backdrop-blur-md
                          transition-all
                          duration-300
                          group-hover:border-amber-300/50
                          group-hover:bg-amber-300
                          group-hover:text-expedition-forest
                        "
                      >
                        <ArrowRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" />
                      </span>
                    </div>
                  </div>

                  {/* featured badge */}
                  {isFeatured && (
                    <div className="absolute left-5 top-5">
                      <span className="rounded-full border border-white/15 bg-black/20 px-3 py-1.5 font-mono text-[9px] uppercase tracking-[0.18em] text-white/80 backdrop-blur-md">
                        Most explored
                      </span>
                    </div>
                  )}
                </motion.a>
              );
            })}
          </div>

          {/* mobile all destinations */}
          <a
            href="/destinations"
            className="
              mt-4
              flex
              items-center
              justify-center
              gap-2
              rounded-xl
              border
              border-white/[0.08]
              bg-white/[0.03]
              py-3
              text-xs
              font-medium
              text-expedition-sand/70
              transition-all
              hover:bg-white/[0.06]
              hover:text-amber-300
              sm:hidden
            "
          >
            Explore all destinations
            <ArrowRight className="h-3.5 w-3.5" />
          </a>
        </motion.div>

        {/* ============================================================
            TRUST / STATS
        ============================================================ */}

        <div className="mt-10">
          <TrustStrip />
        </div>

        <ScrollIndicator />
      </div>

      {/* bottom fade into next section */}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-24 bg-gradient-to-t from-background/20 to-transparent" />
    </section>
  );
}

