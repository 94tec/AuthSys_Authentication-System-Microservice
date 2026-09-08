"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Search, SlidersHorizontal, MapPin, Clock, Users } from "lucide-react";
import { tourApi } from "@/lib/tour-api";
import { formatCurrency } from "@/lib/utils";
import type { TourCategory, TourDifficulty, TourPublic } from "@/types/index-types";

const CATEGORIES: { value: TourCategory | ""; label: string }[] = [
  { value: "",            label: "All categories" },
  { value: "WILDLIFE",   label: "Wildlife" },
  { value: "MOUNTAIN",   label: "Mountain" },
  { value: "BEACH",      label: "Beach" },
  { value: "CULTURAL",   label: "Cultural" },
  { value: "ADVENTURE",  label: "Adventure" },
  { value: "PHOTOGRAPHY",label: "Photography" },
  { value: "FAMILY",     label: "Family" },
  { value: "LUXURY",     label: "Luxury" },
];

const DIFFICULTIES: { value: TourDifficulty | ""; label: string }[] = [
  { value: "",            label: "Any difficulty" },
  { value: "EASY",       label: "Easy" },
  { value: "MODERATE",   label: "Moderate" },
  { value: "CHALLENGING",label: "Challenging" },
  { value: "STRENUOUS",  label: "Strenuous" },
];

function DifficultyPip({ difficulty }: { difficulty: TourDifficulty }) {
  const map: Record<TourDifficulty, string> = {
    EASY:        "bg-green-500",
    MODERATE:    "bg-amber-500",
    CHALLENGING: "bg-orange-500",
    STRENUOUS:   "bg-red-600",
  };
  return (
    <span className="flex items-center gap-1.5 text-xs text-stone">
      <span className={`h-2 w-2 rounded-full ${map[difficulty]}`} />
      {difficulty.charAt(0) + difficulty.slice(1).toLowerCase()}
    </span>
  );
}

function TourCardSkeleton() {
  return (
    <div className="card overflow-hidden">
      <div className="skeleton h-48 w-full" />
      <div className="p-5 space-y-3">
        <div className="skeleton h-5 w-3/4" />
        <div className="skeleton h-4 w-1/2" />
        <div className="skeleton h-4 w-full" />
        <div className="skeleton h-4 w-full" />
        <div className="flex justify-between mt-4">
          <div className="skeleton h-6 w-24" />
          <div className="skeleton h-8 w-20 rounded-md" />
        </div>
      </div>
    </div>
  );
}

export default function ToursPage() {
  const [tours, setTours]         = useState<TourPublic[]>([]);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState("");
  const [category, setCategory]   = useState<TourCategory | "">("");
  const [difficulty, setDifficulty] = useState<TourDifficulty | "">("");

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);

    tourApi.list({
      category:   category   || undefined,
      difficulty: difficulty || undefined,
      query:      search     || undefined,
    })
    .then(setTours)
    .catch((e) => { if (e.name !== "AbortError") console.error(e); })
    .finally(() => setLoading(false));

    return () => controller.abort();
  }, [category, difficulty]);

  // Client-side search filter
  const filtered = search.trim()
    ? tours.filter((t) =>
        t.name.toLowerCase().includes(search.toLowerCase()) ||
        t.destination.toLowerCase().includes(search.toLowerCase())
      )
    : tours;

  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="relative overflow-hidden bg-earth py-24 text-dust">
        <div
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: "url(\"data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23C8860A' fill-opacity='0.3'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E\")",
          }}
        />
        <div className="relative mx-auto max-w-7xl px-4 sm:px-6 text-center">
          <p className="eyebrow text-savanna mb-4">Kenya's finest</p>
          <h1 className="font-display text-5xl font-bold text-dust sm:text-6xl text-balance">
            Find your<br />
            <span className="text-savanna italic">wild place.</span>
          </h1>
          <p className="mt-6 text-lg text-dust/70 max-w-xl mx-auto text-balance">
            From the Maasai Mara at dawn to the peaks of Mount Kenya —
            curated safari experiences with expert guides.
          </p>
        </div>
      </section>

      {/* Filters */}
      <section className="sticky top-[65px] z-30 border-b border-border bg-dust/95 backdrop-blur-sm">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 py-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-stone" />
              <input
                className="input pl-9 py-2"
                placeholder="Search tours or destinations…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <select
                className="input py-2 pr-8 text-sm"
                value={category}
                onChange={(e) => setCategory(e.target.value as TourCategory | "")}
              >
                {CATEGORIES.map((c) => (
                  <option key={c.value} value={c.value}>{c.label}</option>
                ))}
              </select>
              <select
                className="input py-2 pr-8 text-sm"
                value={difficulty}
                onChange={(e) => setDifficulty(e.target.value as TourDifficulty | "")}
              >
                {DIFFICULTIES.map((d) => (
                  <option key={d.value} value={d.value}>{d.label}</option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </section>

      {/* Tour grid */}
      <section className="mx-auto max-w-7xl px-4 sm:px-6 py-10">
        {!loading && filtered.length === 0 ? (
          <div className="py-24 text-center">
            <SlidersHorizontal className="mx-auto h-10 w-10 text-stone/50" />
            <p className="mt-4 text-lg font-medium text-earth">No tours match your filters</p>
            <p className="mt-2 text-sm text-stone">Try adjusting your search or clearing the filters.</p>
            <button
              onClick={() => { setSearch(""); setCategory(""); setDifficulty(""); }}
              className="btn-secondary mt-6"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {loading
              ? Array.from({ length: 6 }).map((_, i) => <TourCardSkeleton key={i} />)
              : filtered.map((tour) => <TourCard key={tour.id} tour={tour} />)
            }
          </div>
        )}
      </section>
    </div>
  );
}

function TourCard({ tour }: { tour: TourPublic }) {
  return (
    <Link href={`/tours/${tour.slug}`} className="card-hover block overflow-hidden group">
      {/* Image */}
      <div className="relative h-48 overflow-hidden bg-stone/10">
        {tour.coverImageUrl ? (
          <img
            src={tour.coverImageUrl}
            alt={tour.name}
            className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-105"
          />
        ) : (
          <div className="flex h-full items-center justify-center">
            <MapPin className="h-10 w-10 text-stone/30" />
          </div>
        )}
        {tour.featured && (
          <span className="absolute top-3 left-3 rounded-full bg-savanna px-2.5 py-0.5 text-xs font-medium text-white">
            Featured
          </span>
        )}
        {/* Horizon line — signature element appears as a bottom accent on cards */}
        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-savanna opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      </div>

      <div className="p-5">
        <p className="eyebrow text-xs mb-1">{tour.destination}</p>
        <h3 className="font-display text-lg font-semibold text-earth leading-snug">
          {tour.name}
        </h3>
        {tour.tagline && (
          <p className="mt-1.5 text-sm text-stone line-clamp-2">{tour.tagline}</p>
        )}

        <div className="mt-4 flex items-center gap-4 text-xs text-stone">
          <span className="flex items-center gap-1">
            <Clock className="h-3.5 w-3.5" />
            {tour.durationDays} {tour.durationDays === 1 ? "day" : "days"}
          </span>
          <span className="flex items-center gap-1">
            <Users className="h-3.5 w-3.5" />
            Max {tour.maxGroupSize}
          </span>
          <DifficultyPip difficulty={tour.difficulty} />
        </div>

        <div className="mt-4 flex items-center justify-between border-t border-border pt-4">
          <div>
            <p className="text-2xs text-stone">From</p>
            <p className="price-tag text-xl">
              {formatCurrency(tour.pricePerPerson, tour.currency)}
            </p>
            <p className="text-2xs text-stone">per person</p>
          </div>
          <span className="btn-primary text-sm px-4 py-2">View tour</span>
        </div>
      </div>
    </Link>
  );
}
