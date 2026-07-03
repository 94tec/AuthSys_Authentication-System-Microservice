"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Search, MapPin, Calendar } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { CATEGORY_LABELS, type TourCategory } from "@/types/tour";

export function Hero() {
  const router = useRouter();
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<string>("");

  function handleSearch() {
    const params = new URLSearchParams();
    if (search) params.set("q", search);
    if (category) params.set("category", category);
    const tourSection = document.getElementById("tours");
    tourSection?.scrollIntoView({ behavior: "smooth" });
    // Dispatch a custom event the tour grid listens for, since this is
    // a single-page landing rather than a separate /search route.
    window.dispatchEvent(
      new CustomEvent("basecamp:search", { detail: { search, category } })
    );
  }

  return (
    <section className="relative overflow-hidden bg-expedition-forest">
      {/* Subtle dot-grid texture, consistent with the auth panel treatment */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.06]"
        style={{
          backgroundImage:
            "radial-gradient(circle at 20% 20%, white 0.5px, transparent 0.5px)",
          backgroundSize: "24px 24px",
        }}
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute -right-32 -top-32 h-96 w-96 rounded-full bg-expedition-clay/10 blur-3xl"
        aria-hidden="true"
      />

      <div className="container relative py-20 sm:py-28 lg:py-32">
        <div className="mx-auto max-w-3xl text-center">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-expedition-clay">
            Curated expeditions, real guides
          </p>
          <h1 className="mt-4 font-display text-4xl font-medium leading-[1.1] tracking-tight text-expedition-sand text-balance sm:text-5xl lg:text-6xl">
            Find the trail that's been waiting for you.
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-base leading-relaxed text-expedition-sand/70 sm:text-lg">
            Safaris, summits, coastlines, and cities — book tours run by
            local experts who know every turn of the trail.
          </p>
        </div>

        {/* Search bar */}
        <div className="mx-auto mt-10 max-w-2xl">
          <div className="flex flex-col gap-2 rounded-2xl border border-expedition-sand/15 bg-expedition-sand/[0.07] p-2.5 backdrop-blur-sm sm:flex-row sm:items-center">
            <div className="flex flex-1 items-center gap-2.5 rounded-xl bg-expedition-sand px-4 py-3">
              <Search className="h-4 w-4 shrink-0 text-expedition-forest/50" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                placeholder="Search destinations, tours…"
                className="w-full bg-transparent text-sm text-expedition-forest placeholder:text-expedition-forest/40 focus:outline-none"
              />
            </div>

            <Select value={category} onValueChange={setCategory}>
              <SelectTrigger className="h-[46px] w-full border-0 bg-expedition-sand text-expedition-forest sm:w-44">
                <div className="flex items-center gap-2">
                  <MapPin className="h-3.5 w-3.5 shrink-0 text-expedition-forest/50" />
                  <SelectValue placeholder="Any category" />
                </div>
              </SelectTrigger>
              <SelectContent>
                {Object.entries(CATEGORY_LABELS).map(([value, label]) => (
                  <SelectItem key={value} value={value}>
                    {label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button
              variant="accent"
              size="lg"
              className="h-[46px] shrink-0"
              onClick={handleSearch}
            >
              <Search className="h-4 w-4" />
              Search tours
            </Button>
          </div>
        </div>

        {/* Trust strip */}
        <div className="mx-auto mt-10 flex max-w-xl flex-wrap items-center justify-center gap-x-8 gap-y-3 text-xs text-expedition-sand/50">
          <span className="flex items-center gap-1.5">
            <Calendar className="h-3.5 w-3.5" />
            Free cancellation on most tours
          </span>
          <span>·</span>
          <span>Local, licensed guides</span>
          <span>·</span>
          <span>Secure booking</span>
        </div>
      </div>
    </section>
  );
}
