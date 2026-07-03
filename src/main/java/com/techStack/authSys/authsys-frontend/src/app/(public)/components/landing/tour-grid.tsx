"use client";

import { useCallback, useEffect, useState } from "react";
import { Compass, RefreshCw } from "lucide-react";
import { TourCard } from "@/app/(public)/components/landing/tour-card";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
//import { tourApi } from "@/lib/tour-api";
import { CATEGORY_LABELS, type TourCategory, type TourSummary } from "@/types/tour";
import type { ApiError } from "@/types/auth";

const CATEGORIES = Object.entries(CATEGORY_LABELS) as [TourCategory, string][];

export function TourGrid() {
  const [tours, setTours] = useState<TourSummary[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState<TourCategory | null>(null);
  const [search, setSearch] = useState("");

  const load = useCallback(
    async (category?: TourCategory | null, q?: string) => {
      setIsLoading(true);
      setError(null);
      try {
        //const data = await tourApi.getTours(0, 12, category ?? undefined, q ?? undefined);
        //setTours(data.content.filter((t) => t.isActive));
      } catch (err) {
        setError((err as ApiError).message || "Couldn't load tours right now.");
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    load();
  }, [load]);

  // Listen for the hero search bar's custom event
  useEffect(() => {
    function handleSearch(e: Event) {
      const detail = (e as CustomEvent).detail as { search?: string; category?: string };
      setSearch(detail.search ?? "");
      const cat = (detail.category as TourCategory) || null;
      setActiveCategory(cat);
      load(cat, detail.search);
    }
    window.addEventListener("basecamp:search", handleSearch);
    return () => window.removeEventListener("basecamp:search", handleSearch);
  }, [load]);

  function handleCategoryClick(category: TourCategory | null) {
    setActiveCategory(category);
    load(category, search);
  }

  return (
    <section id="tours" className="container py-16 sm:py-20">
      <div className="mx-auto max-w-2xl text-center">
        <p className="font-mono text-xs uppercase tracking-[0.15em] text-accent">
          The catalogue
        </p>
        <h2 className="mt-2 font-display text-3xl font-medium tracking-tight sm:text-4xl">
          Tours worth rearranging your year for.
        </h2>
        <p className="mt-3 text-muted-foreground">
          Every trip is run by guides who've walked the trail a hundred times before.
        </p>
      </div>

      {/* Category filter pills */}
      <div className="mt-8 flex flex-wrap items-center justify-center gap-2">
        <button
          onClick={() => handleCategoryClick(null)}
          className={cn(
            "rounded-full border px-4 py-1.5 text-sm font-medium transition-colors",
            activeCategory === null
              ? "border-accent bg-accent text-accent-foreground"
              : "border-border text-muted-foreground hover:border-accent/40 hover:text-foreground"
          )}
        >
          All tours
        </button>
        {CATEGORIES.map(([value, label]) => (
          <button
            key={value}
            onClick={() => handleCategoryClick(value)}
            className={cn(
              "rounded-full border px-4 py-1.5 text-sm font-medium transition-colors",
              activeCategory === value
                ? "border-accent bg-accent text-accent-foreground"
                : "border-border text-muted-foreground hover:border-accent/40 hover:text-foreground"
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Grid */}
      <div className="mt-10">
        {isLoading ? (
          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-80 rounded-xl" />
            ))}
          </div>
        ) : error ? (
          <EmptyState
            icon={RefreshCw}
            title="Couldn't load tours"
            description={error}
            action={
              <Button variant="outline" onClick={() => load(activeCategory, search)}>
                Try again
              </Button>
            }
          />
        ) : tours.length === 0 ? (
          <EmptyState
            icon={Compass}
            title="No tours match yet"
            description="Try a different category, or check back soon — new trips are added regularly."
            action={
              <Button variant="outline" onClick={() => handleCategoryClick(null)}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {tours.map((tour) => (
              <TourCard key={tour.id} tour={tour} />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
